// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEffectiveConfigConcurrentNormalizeNoRace guards the fix for the shared
// Clusters map: effectiveConfig must deep-copy p.config.Clusters so the
// normalize() call (which writes trimmed URLs back into the map) mutates a
// private copy. Without the deep copy, concurrent RPCs (login/status/token)
// would trigger a concurrent map write. Run with -race to detect a regression.
func TestEffectiveConfigConcurrentNormalizeNoRace(t *testing.T) {
	cs := newClusterServer(t)
	p := newClusterAliasPlugin(t, cs, "lab", "", fakeBrowser("t", 3600))

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := p.effectiveConfig(0)
			_ = cfg.Clusters["lab"]
		}()
	}
	wg.Wait()

	cfg := p.effectiveConfig(0)
	require.NotNil(t, cfg.Clusters)
	assert.NotSame(t, &p.config.Clusters, &cfg.Clusters)
}

// TestHandleCallbackPostValidation covers the security guards of the OAuth
// callback POST handler: CSRF state validation, missing token, provider error,
// and malformed payloads, alongside the success path.
func TestHandleCallbackPostValidation(t *testing.T) {
	const state = "state-abc-123"

	post := func(body string) (*httptest.ResponseRecorder, chan webLoginResult, chan error) {
		resultCh := make(chan webLoginResult, 1)
		errCh := make(chan error, 1)
		h := newCallbackHandler(state, resultCh, errCh)
		req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec, resultCh, errCh
	}

	t.Run("state mismatch is rejected (CSRF)", func(t *testing.T) {
		rec, _, errCh := post(`{"access_token":"tok","token_type":"Bearer","state":"wrong"}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		require.Len(t, errCh, 1)
		assert.Contains(t, (<-errCh).Error(), "state mismatch")
	})

	t.Run("missing access_token is rejected", func(t *testing.T) {
		rec, _, errCh := post(`{"token_type":"Bearer","state":"` + state + `"}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		require.Len(t, errCh, 1)
		assert.Contains(t, (<-errCh).Error(), "no access_token")
	})

	t.Run("provider error is surfaced", func(t *testing.T) {
		rec, _, errCh := post(`{"error":"access_denied","error_description":"user denied access"}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		require.Len(t, errCh, 1)
		assert.Contains(t, (<-errCh).Error(), "access_denied")
	})

	t.Run("malformed json is rejected", func(t *testing.T) {
		rec, _, errCh := post(`{not valid json`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		require.Len(t, errCh, 1)
		assert.Contains(t, (<-errCh).Error(), "invalid callback payload")
	})

	t.Run("valid callback delivers the token", func(t *testing.T) {
		rec, resultCh, _ := post(`{"access_token":"tok","token_type":"Bearer","expires_in":"3600","state":"` + state + `"}`)
		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, resultCh, 1)
		res := <-resultCh
		assert.Equal(t, "tok", res.AccessToken)
		assert.Equal(t, "Bearer", res.TokenType)
	})
}

// TestCacheClearClusterSkipsNonMatching verifies per-cluster clear deletes only
// the target cluster's entries, leaves other clusters intact, and tolerates the
// non-JSON active-cluster marker stored under the same prefix.
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

	cacheClearCluster(ctx, logr.Discard(), host, prefix, clusterA)

	a, err := cacheGet(ctx, host, userTokenKey(prefix, clusterA))
	require.NoError(t, err)
	assert.Nil(t, a, "cluster A entry should be cleared")

	b, err := cacheGet(ctx, host, userTokenKey(prefix, clusterB))
	require.NoError(t, err)
	require.NotNil(t, b, "cluster B entry must remain")
	assert.Equal(t, "b", b.AccessToken)

	assert.Equal(t, clusterA, getActiveCluster(ctx, host, prefix))
}
