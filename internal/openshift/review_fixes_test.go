// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEffectiveConfigConcurrentNormalizeNoRace guards the deep copy of the
// shared Clusters map: effectiveConfig must clone p.config.Clusters so
// normalize() mutates a private copy rather than racing across concurrent RPCs.
func TestEffectiveConfigConcurrentNormalizeNoRace(t *testing.T) {
	cs := newClusterServer(t)
	p := newClusterAliasPlugin(t, cs, "lab", "", fakeBrowser("t", 3600))

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg, err := p.effectiveConfig(context.Background(), 0)
			assert.NoError(t, err)
			_ = cfg.Clusters["lab"]
		}()
	}
	wg.Wait()

	cfg, err := p.effectiveConfig(context.Background(), 0)
	require.NoError(t, err)
	require.NotNil(t, cfg.Clusters)
	assert.NotSame(t, &p.config.Clusters, &cfg.Clusters)
}

// TestHandleCallbackPostValidation covers the security guards of the implicit
// OAuth callback server: bridge CSP, CSRF state validation (without poisoning
// ResultChan), cross-origin rejection, missing token, provider error, and
// malformed payloads, alongside the deferred-completion success path.
func TestHandleCallbackPostValidation(t *testing.T) {
	const state = "state-abc-123"

	postForm := func(t *testing.T, csURL, rawBody, origin string) *http.Response {
		t.Helper()
		parsed, err := url.Parse(csURL)
		require.NoError(t, err)
		tokenURL := parsed.Scheme + "://" + parsed.Host + "/token"

		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL, strings.NewReader(rawBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("bridge GET serves script-hash CSP and sandboxed iframe renderer", func(t *testing.T) {
		cs, err := startImplicitCallback(context.Background(), "127.0.0.1", 0, state, nil)
		require.NoError(t, err)
		defer func() { _ = cs.Close() }()

		getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, cs.RedirectURI, nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(getReq)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "script-src 'sha256-")
		assert.Contains(t, string(body), `frame.setAttribute("sandbox", "")`)
	})

	t.Run("state mismatch and missing state are rejected (403) without poisoning ResultChan", func(t *testing.T) {
		cs, err := startImplicitCallback(context.Background(), "127.0.0.1", 0, state, nil)
		require.NoError(t, err)
		defer func() { _ = cs.Close() }()

		for _, payload := range []string{
			"access_token=tok&token_type=Bearer&state=wrong",
			"access_token=tok&token_type=Bearer",
			"error=access_denied&state=wrong",
		} {
			resp := postForm(t, cs.RedirectURI, payload, "")
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		}

		select {
		case res := <-cs.ResultChan():
			t.Fatalf("forged callback must not deliver a result: %+v", res)
		default:
		}
	})

	t.Run("cross-origin POST is rejected (403)", func(t *testing.T) {
		cs, err := startImplicitCallback(context.Background(), "127.0.0.1", 0, state, nil)
		require.NoError(t, err)
		defer func() { _ = cs.Close() }()

		resp := postForm(t, cs.RedirectURI, "access_token=tok&state="+state, "https://evil.example.com")
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("missing access_token is rejected", func(t *testing.T) {
		cs, err := startImplicitCallback(context.Background(), "127.0.0.1", 0, state, nil)
		require.NoError(t, err)
		defer func() { _ = cs.Close() }()

		resp := postForm(t, cs.RedirectURI, "token_type=Bearer&state="+state, "")
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		res := <-cs.ResultChan()
		require.Error(t, res.Err)
		assert.Contains(t, res.Err.Error(), "no access_token")
	})

	t.Run("provider error is surfaced", func(t *testing.T) {
		cs, err := startImplicitCallback(context.Background(), "127.0.0.1", 0, state, nil)
		require.NoError(t, err)
		defer func() { _ = cs.Close() }()

		resp := postForm(t, cs.RedirectURI, "error=access_denied&error_description=user+denied+access&state="+state, "")
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		res := <-cs.ResultChan()
		require.Error(t, res.Err)
		assert.Contains(t, res.Err.Error(), "access_denied")
	})

	t.Run("malformed form body is rejected", func(t *testing.T) {
		cs, err := startImplicitCallback(context.Background(), "127.0.0.1", 0, state, nil)
		require.NoError(t, err)
		defer func() { _ = cs.Close() }()

		resp := postForm(t, cs.RedirectURI, "access_token=%ZZ", "")
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("valid callback delivers the token and settles 200 on Complete(true)", func(t *testing.T) {
		cs, err := startImplicitCallback(context.Background(), "127.0.0.1", 0, state, nil)
		require.NoError(t, err)
		defer func() { _ = cs.Close() }()

		respCh := make(chan *http.Response, 1)
		go func() {
			respCh <- postForm(t, cs.RedirectURI, "access_token=tok&token_type=Bearer&expires_in=3600&state="+state, "")
		}()

		res := <-cs.ResultChan()
		require.NoError(t, res.Err)
		assert.Equal(t, "tok", res.AccessToken)
		assert.Equal(t, "Bearer", res.TokenType)
		assert.Equal(t, "3600", res.ExpiresIn)

		cs.Complete(true)
		resp := <-respCh
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NoError(t, cs.Shutdown(context.Background()))
	})
}

// TestCacheClearClusterSkipsNonMatching verifies per-cluster clear deletes only
// the target cluster's entries, leaves other clusters intact, and promotes the
// remaining usable cluster when the cleared cluster was active.
func TestCacheClearClusterSkipsNonMatching(t *testing.T) {
	fake := newFakeHostService()
	ctx := hostContext(fake)
	host := newFakeHostClient(fake)
	prefix := profileKeyPrefix("")

	clusterA := "https://api.a.example:6443"
	clusterB := "https://api.b.example:6443"
	require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterA), &cacheEntry{AccessToken: "a", APIServer: clusterA, Kind: kindUser}))
	require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterB), &cacheEntry{AccessToken: "b", APIServer: clusterB, Kind: kindUser}))
	require.NoError(t, setActiveCluster(ctx, host, prefix, clusterA))

	require.NoError(t, cacheClearCluster(ctx, logr.Discard(), host, prefix, clusterA))

	a, err := cacheGet(ctx, host, userTokenKey(prefix, clusterA))
	require.NoError(t, err)
	assert.Nil(t, a, "cluster A entry should be cleared")

	b, err := cacheGet(ctx, host, userTokenKey(prefix, clusterB))
	require.NoError(t, err)
	require.NotNil(t, b, "cluster B entry must remain")
	assert.Equal(t, "b", b.AccessToken)

	assert.Equal(t, clusterB, getActiveCluster(ctx, host, prefix), "remaining usable cluster must be promoted to active")
}
