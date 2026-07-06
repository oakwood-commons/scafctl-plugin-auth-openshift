// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSAScope(t *testing.T) {
	tests := []struct {
		name    string
		scope   string
		wantOK  bool
		wantNS  string
		wantSA  string
		wantAud string
	}{
		{name: "empty", scope: "", wantOK: false},
		{name: "user token marker not SA", scope: "user", wantOK: false},
		{name: "shorthand", scope: "infra-auto/pipeline", wantOK: true, wantNS: "infra-auto", wantSA: "pipeline"},
		{name: "shorthand with audience", scope: "infra-auto/pipeline@openshift", wantOK: true, wantNS: "infra-auto", wantSA: "pipeline", wantAud: "openshift"},
		{name: "canonical", scope: "system:serviceaccount:ns1:sa1", wantOK: true, wantNS: "ns1", wantSA: "sa1"},
		{name: "canonical with audience", scope: "system:serviceaccount:ns1:sa1@aud", wantOK: true, wantNS: "ns1", wantSA: "sa1", wantAud: "aud"},
		{name: "too many slashes", scope: "a/b/c", wantOK: false},
		{name: "canonical missing parts", scope: "system:serviceaccount:ns1", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sa, ok := parseSAScope(tc.scope)
			assert.Equal(t, tc.wantOK, ok)
			if ok {
				assert.Equal(t, tc.wantNS, sa.Namespace)
				assert.Equal(t, tc.wantSA, sa.ServiceAccount)
				assert.Equal(t, tc.wantAud, sa.Audience)
			}
		})
	}
}

func TestConfigApplySettingsAndNormalize(t *testing.T) {
	c := DefaultConfig()
	settings := map[string]json.RawMessage{
		"apiServerUrl":  json.RawMessage(`"https://api.example.test:6443/"`),
		"oauthClientId": json.RawMessage(`"custom-client"`),
		"callbackPort":  json.RawMessage(`9000`),
	}
	require.NoError(t, c.applySettings(settings))
	assert.Equal(t, "https://api.example.test:6443", c.APIServerURL, "trailing slash trimmed")
	assert.Equal(t, "custom-client", c.OAuthClientID)
	assert.Equal(t, 9000, c.CallbackPort)
	assert.Equal(t, DefaultCallbackHost, c.CallbackHost)
}

func TestConfigDefaults(t *testing.T) {
	c := DefaultConfig()
	c.OAuthClientID = ""
	c.CallbackHost = ""
	c.LoginTimeout = 0
	c.normalize()
	assert.Equal(t, DefaultOAuthClientID, c.OAuthClientID)
	assert.Equal(t, DefaultCallbackHost, c.CallbackHost)
	assert.Equal(t, DefaultLoginTimeout, c.LoginTimeout)
}

func TestDiscoverOAuthMetadata(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, oauthMetadata{
				Issuer:                "https://issuer",
				AuthorizationEndpoint: "https://oauth/authorize",
				TokenEndpoint:         "https://oauth/token",
			})
		}))
		defer srv.Close()

		meta, err := discoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://oauth/authorize", meta.AuthorizationEndpoint)
	})

	t.Run("missing authorization endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, oauthMetadata{Issuer: "x"})
		}))
		defer srv.Close()

		_, err := discoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization_endpoint")
	})

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := discoverOAuthMetadata(context.Background(), srv.Client(), srv.URL)
		require.Error(t, err)
	})

	t.Run("empty api server", func(t *testing.T) {
		_, err := discoverOAuthMetadata(context.Background(), http.DefaultClient, "")
		require.Error(t, err)
	})
}

func TestExpiryFromExpiresIn(t *testing.T) {
	assert.True(t, expiryFromExpiresIn("").IsZero())
	assert.True(t, expiryFromExpiresIn("bad").IsZero())
	assert.True(t, expiryFromExpiresIn("0").IsZero())
	got := expiryFromExpiresIn("3600")
	assert.WithinDuration(t, time.Now().Add(time.Hour), got, 5*time.Second)
}

func TestCacheEntryUsable(t *testing.T) {
	assert.False(t, (&cacheEntry{}).isUsable(), "no token")
	assert.True(t, (&cacheEntry{AccessToken: "x"}).isUsable(), "no expiry assumed usable")
	assert.True(t, (&cacheEntry{AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour)}).isUsable())
	assert.False(t, (&cacheEntry{AccessToken: "x", ExpiresAt: time.Now().Add(-time.Hour)}).isUsable())
	assert.False(t, (&cacheEntry{AccessToken: "x", ExpiresAt: time.Now().Add(10 * time.Second)}).isUsable(), "within leeway")
}

func TestBuildAuthorizeURL(t *testing.T) {
	got := buildAuthorizeURL("https://oauth/authorize", "openshift-cli-client", "http://127.0.0.1:5000/callback", "abc123")
	assert.Contains(t, got, "client_id=openshift-cli-client")
	assert.Contains(t, got, "response_type=token")
	assert.Contains(t, got, "state=abc123")
	assert.Contains(t, got, "redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback")
}

func TestBuildRedirectURI(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "ipv4", host: "127.0.0.1", port: 5000, want: "http://127.0.0.1:5000/callback"},
		{name: "hostname", host: "localhost", port: 8080, want: "http://localhost:8080/callback"},
		{name: "ipv6 loopback is bracketed", host: "::1", port: 5000, want: "http://[::1]:5000/callback"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, buildRedirectURI(tc.host, tc.port))
		})
	}
}

func TestMintServiceAccountTokenValidation(t *testing.T) {
	_, err := mintServiceAccountToken(context.Background(), http.DefaultClient, mintSAParams{})
	require.Error(t, err)

	_, err = mintServiceAccountToken(context.Background(), http.DefaultClient, mintSAParams{
		APIServerURL: "https://api", Namespace: "ns", ServiceAccount: "sa",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")

	// Path-segment injection via a namespace containing "/" is rejected before
	// any request is built.
	_, err = mintServiceAccountToken(context.Background(), http.DefaultClient, mintSAParams{
		APIServerURL: "https://api", Namespace: "ns/../../secrets", ServiceAccount: "sa", BearerToken: "tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid namespace")

	// Likewise for the service account name.
	_, err = mintServiceAccountToken(context.Background(), http.DefaultClient, mintSAParams{
		APIServerURL: "https://api", Namespace: "ns", ServiceAccount: "sa/evil", BearerToken: "tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid service account")
}

func TestValidateK8sName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "simple", input: "default", wantErr: false},
		{name: "with hyphen", input: "infra-auto", wantErr: false},
		{name: "with dot", input: "pipeline.runner", wantErr: false},
		{name: "alphanumeric", input: "sa123", wantErr: false},
		{name: "slash rejected", input: "ns/sa", wantErr: true},
		{name: "parent traversal rejected", input: "../secrets", wantErr: true},
		{name: "question mark rejected", input: "ns?x", wantErr: true},
		{name: "hash rejected", input: "ns#x", wantErr: true},
		{name: "whitespace rejected", input: "ns sa", wantErr: true},
		{name: "newline rejected", input: "ns\nsa", wantErr: true},
		{name: "uppercase rejected", input: "Default", wantErr: true},
		{name: "empty rejected", input: "", wantErr: true},
		{name: "leading hyphen rejected", input: "-ns", wantErr: true},
		{name: "too long rejected", input: strings.Repeat("a", 254), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateK8sName(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCacheEntryUsableFor(t *testing.T) {
	// minValidFor below the default leeway falls back to the leeway window.
	assert.False(t, (&cacheEntry{}).isUsableFor(time.Hour), "no token")
	assert.True(t, (&cacheEntry{AccessToken: "x"}).isUsableFor(time.Hour), "no expiry assumed usable")

	// Token valid for ~30m: usable for the default leeway but not for a 1h demand.
	entry := &cacheEntry{AccessToken: "x", ExpiresAt: time.Now().Add(30 * time.Minute)}
	assert.True(t, entry.isUsableFor(0))
	assert.True(t, entry.isUsableFor(10*time.Minute))
	assert.False(t, entry.isUsableFor(time.Hour), "demand exceeds remaining lifetime")
}

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"127.0.0.5", true},
		{"0.0.0.0", false},
		{"192.168.1.10", false},
		{"example.com", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.want, isLoopbackHost(tc.host))
		})
	}
}

func TestScopeForEntry(t *testing.T) {
	assert.Equal(t, "ns/sa@aud", scopeForEntry(&cacheEntry{
		Kind: kindServiceAccount, Namespace: "ns", ServiceAccount: "sa", Audience: "aud",
	}))
	assert.Equal(t, "ns/sa", scopeForEntry(&cacheEntry{
		Kind: kindServiceAccount, Namespace: "ns", ServiceAccount: "sa",
	}), "no trailing @ when audience empty")
	// User (login) sessions have no per-request scope; the cluster is reported
	// via Hostname instead (see hostnameForEntry).
	assert.Empty(t, scopeForEntry(&cacheEntry{Kind: kindUser, APIServer: "https://api"}))
	assert.Empty(t, scopeForEntry(&cacheEntry{Kind: kindUser, Username: "jane"}))
}

func TestHostnameForEntry(t *testing.T) {
	assert.Equal(t, "https://api", hostnameForEntry(&cacheEntry{Kind: kindUser, APIServer: "https://api"}))
	assert.Empty(t, hostnameForEntry(&cacheEntry{Kind: kindServiceAccount, APIServer: "https://api"}),
		"service-account tokens are not login sessions and report no instance hostname")
}

func TestProfileKeyPrefix(t *testing.T) {
	// Stable and deterministic per profile.
	assert.Equal(t, profileKeyPrefix(""), profileKeyPrefix(""))
	assert.True(t, strings.HasPrefix(profileKeyPrefix("work"), keyPrefix))

	// Distinct profiles yield distinct, non-overlapping prefixes.
	a := profileKeyPrefix("work")
	b := profileKeyPrefix("personal")
	assert.NotEqual(t, a, b)
	assert.NotEqual(t, profileKeyPrefix(""), a)

	// Keys built from distinct profiles never collide.
	assert.NotEqual(t, userTokenKey(a, "https://api"), userTokenKey(b, "https://api"))
}
