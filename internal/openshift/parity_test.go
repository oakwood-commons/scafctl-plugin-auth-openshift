// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TestMultiClusterSimultaneousLoginAndGetToken verifies multi-cluster token
// routing: two logins to distinct clusters store distinct tokens keyed by
// canonical cluster URL, GetToken(Hostname=clusterA) and
// GetToken(Hostname=clusterB) succeed simultaneously with zero re-login across
// URL/alias/casing variations, empty Hostname preserves active-cluster fallback
// (including active-cluster promotion when the active cluster is logged out),
// and service-account tokens are isolated per cluster.
func TestMultiClusterSimultaneousLoginAndGetToken(t *testing.T) {
	clusterA := newClusterServer(t)
	clusterA.whoamiName = "alice"
	clusterA.saToken = "sa-token-cluster-a"

	clusterB := newClusterServer(t)
	clusterB.whoamiName = "bob"
	clusterB.saToken = "sa-token-cluster-b"

	tokenByServer := map[string]string{
		clusterA.url(): "user-token-cluster-a",
		clusterB.url(): "user-token-cluster-b",
	}

	var loginCountMu sync.Mutex
	var loginCount int
	browser := func(ctx context.Context, rawURL string) error {
		loginCountMu.Lock()
		loginCount++
		loginCountMu.Unlock()

		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		origin := u.Scheme + "://" + u.Host
		tok, ok := tokenByServer[origin]
		if !ok {
			return fmt.Errorf("unexpected authorize origin %q", origin)
		}
		return fakeBrowser(tok, 3600)(ctx, rawURL)
	}

	p := &Plugin{
		http:    http.DefaultClient,
		browser: browser,
	}
	clustersRaw, err := json.Marshal(map[string]Cluster{
		"cluster-a": {URL: strings.ToUpper(clusterA.url()) + "/"},
		"clusterb":  {URL: clusterB.url() + "///"},
	})
	require.NoError(t, err)
	require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		Settings: map[string]json.RawMessage{
			HandlerName: json.RawMessage(fmt.Sprintf(`{"clusters":%s,"loginTimeout":"3s"}`, string(clustersRaw))),
		},
	}))

	// Verify both CapHostname and CapTokenHostname ("token_hostname") are advertised.
	handlers, err := p.GetAuthHandlers(context.Background())
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	assert.Contains(t, handlers[0].Capabilities, auth.CapHostname)
	assert.Contains(t, handlers[0].Capabilities, auth.CapTokenHostname)
	assert.Equal(t, "token_hostname", string(auth.CapTokenHostname))

	fake := newFakeHostService()
	ctx := hostContext(fake)

	// 1. Login to cluster A (via alias), then cluster B (via mixed-case alias matching Viper-lowercased key).
	respA, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Hostname: "cluster-a"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "alice", respA.Claims.Username)

	respB, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Hostname: "ClusterB"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "bob", respB.Claims.Username)
	assert.Equal(t, 2, loginCount)

	// 2. Both clusters coexist in ListCachedTokens with canonical Hostname values.
	cached, err := p.ListCachedTokens(ctx, HandlerName)
	require.NoError(t, err)
	require.Len(t, cached, 2)

	// 3. Simultaneous GetToken calls across clusterA and clusterB (via URL,
	// mixed-case URL, trailing slash, "user" scope, and alias) return each
	// cluster's own token with zero re-logins.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tok, gerr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
				Hostname: strings.ToUpper(clusterA.url()) + "/",
				Scope:    "user",
			})
			if assert.NoError(t, gerr) {
				assert.Equal(t, "user-token-cluster-a", tok.AccessToken)
			}
			aliasTok, aerr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: "cluster-a"})
			if assert.NoError(t, aerr) {
				assert.Equal(t, "user-token-cluster-a", aliasTok.AccessToken)
			}
		}()
		go func() {
			defer wg.Done()
			tok, gerr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
				Hostname: clusterB.url(),
				Scope:    "user:full",
			})
			if assert.NoError(t, gerr) {
				assert.Equal(t, "user-token-cluster-b", tok.AccessToken)
			}
			aliasTok, aerr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: "ClusterB"})
			if assert.NoError(t, aerr) {
				assert.Equal(t, "user-token-cluster-b", aliasTok.AccessToken)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 2, loginCount, "token retrieval must not re-run interactive login")

	// 4. Empty Hostname falls back to the most-recent active cluster (cluster B).
	defaultTok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, "user-token-cluster-b", defaultTok.AccessToken)

	// 5. Service-account tokens are minted and cached independently per cluster.
	saA, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
		Hostname: clusterA.url(),
		Scope:    "infra/deployer@openshift",
	})
	require.NoError(t, err)
	assert.Equal(t, "sa-token-cluster-a", saA.AccessToken)

	saB, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
		Hostname: clusterB.url(),
		Scope:    "infra/deployer@openshift",
	})
	require.NoError(t, err)
	assert.Equal(t, "sa-token-cluster-b", saB.AccessToken)

	// 6. GetStatus honors per-cluster Hostname and empty-Hostname active fallback.
	stA, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{Hostname: clusterA.url()})
	require.NoError(t, err)
	assert.True(t, stA.Authenticated)
	assert.Equal(t, "alice", stA.Claims.Username)
	assert.Equal(t, clusterA.url(), stA.Hostname)

	stDefault, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, stDefault.Authenticated)
	assert.Equal(t, "bob", stDefault.Claims.Username)

	// 7. Logging out of the ACTIVE cluster (cluster B) clears cluster B's user
	// and SA tokens AND promotes remaining live cluster A to active so
	// empty-Hostname GetStatus and GetToken continue working.
	require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: "ClusterB"}))

	_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: clusterB.url()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")

	_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: clusterB.url(), Scope: "infra/deployer@openshift"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")

	promotedSt, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, promotedSt.Authenticated)
	assert.Equal(t, "alice", promotedSt.Claims.Username)

	promotedTok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, "user-token-cluster-a", promotedTok.AccessToken)
}

func TestCanonicalClusterURLNormalization(t *testing.T) {
	// Assemble synthetic credential-bearing inputs at runtime so static secret
	// scanners do not flag deliberate redaction test fixtures as embedded URI
	// credentials.
	joinParts := func(parts ...string) string { return strings.Join(parts, "") }

	tests := []struct {
		name        string
		input       string
		want        string
		wantErr     bool
		errContains string
		notContains string
	}{
		{
			name:  "mixed case scheme and host with trailing slash",
			input: "HTTPS://API.ClusterA.Example.COM:6443///",
			want:  "https://api.clustera.example.com:6443",
		},
		{
			name:  "default https port 443 stripped",
			input: "https://api.aro.example.com:443/",
			want:  "https://api.aro.example.com",
		},
		{
			name:  "default http port 80 stripped",
			input: "http://127.0.0.1:80/",
			want:  "http://127.0.0.1",
		},
		{
			name:  "trailing DNS dot stripped",
			input: "https://api.cluster.example.com.:6443",
			want:  "https://api.cluster.example.com:6443",
		},
		{
			name:  "bare host and port defaults to https",
			input: "API.Cluster.Example.com:6443",
			want:  "https://api.cluster.example.com:6443",
		},
		{
			name:  "ipv6 with default https port keeps brackets",
			input: "https://[::1]:443/",
			want:  "https://[::1]",
		},
		{
			name:  "expanded ipv6 compressed canonically",
			input: "https://[2001:0db8:0000:0000:0000:0000:0000:0001]:6443/",
			want:  "https://[2001:db8::1]:6443",
		},
		{
			name:  "ipv6 with custom port",
			input: "[::1]:6443",
			want:  "https://[::1]:6443",
		},
		{
			name:  "scoped ipv6 expanded compressed while preserving uppercase zone casing",
			input: "HTTPS://[FE80:0000:0000:0000:0000:0000:0000:0001%25EN0]:6443/",
			want:  "https://[fe80::1%25EN0]:6443",
		},
		{
			name:  "scoped ipv6 strips default port 443 and preserves hex-prefix zone",
			input: "https://[fe80::1%25ef0]:443/",
			want:  "https://[fe80::1%25ef0]",
		},
		{
			name:  "scoped ipv6 preserves literal 25-prefixed zone without collapsing to en0",
			input: "https://[fe80::1%2525en0]:6443/",
			want:  "https://[fe80::1%2525en0]:6443",
		},
		{
			name:  "proxy subpath preserved without trailing slash",
			input: "https://proxy.example.com/k8s/clusters/c-1/",
			want:  "https://proxy.example.com/k8s/clusters/c-1",
		},
		{
			name:        "unsupported scheme rejected",
			input:       "ftp://api.example.com:6443",
			wantErr:     true,
			errContains: "unsupported scheme",
		},
		{
			name:        "malformed single-slash http prefix rejected",
			input:       "http:/api.example.com:6443",
			wantErr:     true,
			errContains: "malformed scheme",
		},
		{
			name:        "javascript prefix without slashes rejected",
			input:       "javascript:80",
			wantErr:     true,
			errContains: "malformed scheme",
		},
		{
			name:        "path traversal rejected",
			input:       "https://proxy.example.com/k8s/../secret",
			wantErr:     true,
			errContains: "path traversal",
		},
		{
			name:        "encoded slash rejected",
			input:       "https://proxy.example.com/k8s%2fsecret",
			wantErr:     true,
			errContains: "path traversal",
		},
		{
			name:        "user credentials rejected and password redacted from error",
			input:       joinParts("https://", "admin", ":", "SuperSecretPass123", "@api.example.com:6443"),
			wantErr:     true,
			errContains: "user credentials",
			notContains: "SuperSecretPass123",
		},
		{
			name:        "malformed userinfo with unescaped question mark redacts password",
			input:       joinParts("https://", "alice", ":", "SecretQmark123", "?extra@api.example.com"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "SecretQmark123",
		},
		{
			name:        "malformed userinfo with unescaped fragment hash redacts password",
			input:       joinParts("https://", "alice", ":", "SecretHash123", "#frag@api.example.com"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "SecretHash123",
		},
		{
			name:        "malformed userinfo with unescaped slash redacts password",
			input:       joinParts("https://", "alice", ":", "SecretSlash123", "/part@api.example.com"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "SecretSlash123",
		},
		{
			name:        "schemeless userinfo with unescaped delimiters redacts password",
			input:       joinParts("alice", ":", "BareSecret123", "?x#y/z@api.example.com:6443"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "BareSecret123",
		},
		{
			name:        "malformed userinfo missing host delimiter redacts password",
			input:       joinParts("https://", "alice", ":", "NoAtSecret123"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "NoAtSecret123",
		},
		{
			name:        "schemeless userinfo with embedded scheme in query redacts password",
			input:       joinParts("alice", ":", "EmbeddedSchemeSecret123", "@api.example.com?redirect=https://other.example.com"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "EmbeddedSchemeSecret123",
		},
		{
			name:        "schemeless query token with embedded scheme redacts token",
			input:       joinParts("api.example.com:6443?access_token=", "QueryEmbeddedSecret999", "&cb=http://127.0.0.1"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "QueryEmbeddedSecret999",
		},
		{
			name:        "schemeless userinfo containing scheme separator redacts password",
			input:       joinParts("alice", ":", "Sec", "://", "ret999", "@api.example.com"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "Sec",
		},
		{
			name:        "unclosed bracket authority with colon secret redacts password",
			input:       joinParts("https://[alice", ":", "BracketSecret123"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "BracketSecret123",
		},
		{
			name:        "single-slash scheme typo missing host delimiter redacts password",
			input:       joinParts("https:/alice", ":", "SingleSlashSecret123"),
			wantErr:     true,
			errContains: "invalid cluster endpoint",
			notContains: "SingleSlashSecret123",
		},
		{
			name:        "query token rejected and redacted from error",
			input:       joinParts("https://api.example.com:6443?access_token=", "QuerySecret999"),
			wantErr:     true,
			errContains: "query and fragment",
			notContains: "QuerySecret999",
		},
		{
			name:        "fragment token rejected and redacted from error",
			input:       joinParts("https://api.example.com:6443#access_token=", "FragSecret999"),
			wantErr:     true,
			errContains: "query and fragment",
			notContains: "FragSecret999",
		},
		{
			name:        "hostless port rejected",
			input:       "https://:6443",
			wantErr:     true,
			errContains: "missing host",
		},
		{
			name:        "out of range port rejected",
			input:       "https://api.example.com:70000",
			wantErr:     true,
			errContains: "invalid port",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeEndpoint(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				if tc.notContains != "" {
					assert.NotContains(t, err.Error(), tc.notContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("userTokenKey matches across equivalent URL representations", func(t *testing.T) {
		prefix := profileKeyPrefix("work")
		k1 := userTokenKey(prefix, "HTTPS://API.Cluster.Example.COM:443/")
		k2 := userTokenKey(prefix, "api.cluster.example.com")
		k3 := userTokenKey(prefix, "https://api.cluster.example.com.:443")
		assert.Equal(t, k1, k2)
		assert.Equal(t, k2, k3)

		zCompressed := userTokenKey(prefix, "https://[fe80::1%25EN0]:6443")
		zExpanded := userTokenKey(prefix, "https://[FE80:0000:0000:0000:0000:0000:0000:0001%25EN0]:6443/")
		zLowerZone := userTokenKey(prefix, "https://[fe80::1%25en0]:6443")
		assert.Equal(t, zCompressed, zExpanded, "equivalent scoped IPv6 spellings must share canonical cache key")
		assert.NotEqual(t, zCompressed, zLowerZone, "distinct case-sensitive IPv6 zone IDs must not share cache keys")
	})
}

func TestSecurityGuardsDiscoveryRedirectScopeAndSanitization(t *testing.T) {
	t.Run("OAuth discovery rejects fragment hijack, pre-seeded redirect_uri, and https->http downgrade", func(t *testing.T) {
		cases := []struct {
			name      string
			apiServer string
			authz     string
			wantErr   string
		}{
			{
				name:      "fragment injection rejected",
				apiServer: "https://api.cluster.example.com:6443",
				authz:     "https://sso.example.com/oauth/authorize?client_id=attacker&redirect_uri=https://evil.example/cb#",
				wantErr:   "fragment",
			},
			{
				name:      "pre-populated redirect_uri rejected",
				apiServer: "https://api.cluster.example.com:6443",
				authz:     "https://sso.example.com/oauth/authorize?redirect_uri=https://evil.example/cb",
				wantErr:   "redirect_uri",
			},
			{
				name:      "https to non-loopback http downgrade rejected",
				apiServer: "https://api.cluster.example.com:6443",
				authz:     "http://sso.example.com/oauth/authorize",
				wantErr:   "cleartext http",
			},
			{
				name:      "control characters in authorization_endpoint rejected",
				apiServer: "https://api.cluster.example.com:6443",
				authz:     "https://sso.example.com/oauth/\x1b[31mauthorize",
				wantErr:   "control characters",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := validateAuthorizationEndpoint(tc.authz, tc.apiServer)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			})
		}

		// Benign custom IdP query param is preserved alongside OAuth params.
		validAuthz, err := validateAuthorizationEndpoint("https://sso.example.com/oauth/authorize?idp=enterprise", "https://api.cluster.example.com:6443")
		require.NoError(t, err)
		built := buildAuthorizeURL(validAuthz, "openshift-cli-client", "http://127.0.0.1:9000/callback", "st123")
		parsed, err := url.Parse(built)
		require.NoError(t, err)
		assert.Equal(t, "enterprise", parsed.Query().Get("idp"))
		assert.Equal(t, "openshift-cli-client", parsed.Query().Get("client_id"))
	})

	t.Run("managed HTTP client strips Authorization on cross-origin redirect and blocks insecure cross-origin redirects", func(t *testing.T) {
		var targetGotAuth atomic.Value
		targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetGotAuth.Store(r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}))
		defer targetSrv.Close()

		redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, targetSrv.URL+"/landed", http.StatusFound)
		}))
		defer redirectSrv.Close()

		stdClient := newHTTPClient(5*time.Second, false)
		status, _, err := getJSON(context.Background(), stdClient, redirectSrv.URL+"/start", "secret-bearer-token")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Empty(t, targetGotAuth.Load(), "Authorization header must be stripped across port/host redirect")

		insecureClient := newHTTPClient(5*time.Second, true)
		_, _, err = getJSON(context.Background(), insecureClient, redirectSrv.URL+"/start", "secret-bearer-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insecureSkipTlsVerify")

		// Redirects between implicit and explicit HTTP/HTTPS default ports target
		// the same origin: Authorization must be preserved and insecureSkipTlsVerify
		// must allow the redirect, while non-default port changes remain cross-origin.
		redirectCases := []struct {
			name           string
			startURL       string
			targetURL      string
			wantSameOrigin bool
		}{
			{
				name:           "https implicit to explicit default port 443",
				startURL:       "https://api.example.com/start",
				targetURL:      "https://API.Example.COM:443/landed",
				wantSameOrigin: true,
			},
			{
				name:           "https explicit default port 443 to implicit",
				startURL:       "https://api.example.com:443/start",
				targetURL:      "https://api.example.com/landed",
				wantSameOrigin: true,
			},
			{
				name:           "https ipv6 implicit to explicit 443",
				startURL:       "https://[::1]/start",
				targetURL:      "https://[::1]:443/landed",
				wantSameOrigin: true,
			},
			{
				name:           "https compressed ipv6 to expanded ipv6 with explicit 443",
				startURL:       "https://[::1]/start",
				targetURL:      "https://[0:0:0:0:0:0:0:1]:443/landed",
				wantSameOrigin: true,
			},
			{
				name:           "https compressed ipv6 custom port to expanded ipv6 custom port",
				startURL:       "https://[2001:db8::1]:6443/start",
				targetURL:      "https://[2001:0db8:0000:0000:0000:0000:0000:0001]:6443/landed",
				wantSameOrigin: true,
			},
			{
				name:           "https scoped ipv6 compressed to expanded same zone",
				startURL:       "https://[fe80::1%25en0]/start",
				targetURL:      "https://[fe80:0:0:0:0:0:0:1%25en0]:443/landed",
				wantSameOrigin: true,
			},
			{
				name:           "https scoped ipv6 different zone casing is cross-origin",
				startURL:       "https://[fe80::1%25en0]/start",
				targetURL:      "https://[fe80::1%25EN0]/landed",
				wantSameOrigin: false,
			},
			{
				name:           "https scoped ipv6 zone 25en0 vs zone en0 is cross-origin",
				startURL:       "https://[fe80::1%25en0]/start",
				targetURL:      "https://[fe80::1%2525en0]/landed",
				wantSameOrigin: false,
			},
			{
				name:           "https ipv4 to ipv4-mapped ipv6 is cross-origin",
				startURL:       "https://127.0.0.1/start",
				targetURL:      "https://[::ffff:127.0.0.1]/landed",
				wantSameOrigin: false,
			},
			{
				name:           "http explicit default port 80 to implicit",
				startURL:       "http://api.example.com:80/start",
				targetURL:      "http://api.example.com/landed",
				wantSameOrigin: true,
			},
			{
				name:           "https implicit 443 to non-default 8443 is cross-origin",
				startURL:       "https://api.example.com/start",
				targetURL:      "https://api.example.com:8443/landed",
				wantSameOrigin: false,
			},
		}
		for _, rc := range redirectCases {
			t.Run(rc.name, func(t *testing.T) {
				var landedAuth string
				rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/start" {
						hdr := make(http.Header)
						hdr.Set("Location", rc.targetURL)
						return &http.Response{
							StatusCode: http.StatusFound,
							Header:     hdr,
							Body:       io.NopCloser(strings.NewReader("")),
							Request:    r,
						}, nil
					}
					landedAuth = r.Header.Get("Authorization")
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("{}")),
						Request:    r,
					}, nil
				})

				cStd := newHTTPClient(5*time.Second, false)
				cStd.Transport = rt
				st, _, rerr := getJSON(context.Background(), cStd, rc.startURL, "secret-bearer-token")
				require.NoError(t, rerr)
				assert.Equal(t, http.StatusOK, st)
				if rc.wantSameOrigin {
					assert.Equal(t, "Bearer secret-bearer-token", landedAuth)
				} else {
					assert.Empty(t, landedAuth)
				}

				cIns := newHTTPClient(5*time.Second, true)
				cIns.Transport = rt
				_, _, ierr := getJSON(context.Background(), cIns, rc.startURL, "secret-bearer-token")
				if rc.wantSameOrigin {
					require.NoError(t, ierr)
				} else {
					require.Error(t, ierr)
					assert.Contains(t, ierr.Error(), "insecureSkipTlsVerify")
				}
			})
		}

		// Multi-hop redirect bouncing off a cross-origin intermediate back to the
		// initial origin must NOT re-attach Authorization.
		var bounceAuth string
		bounceRT := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			hdr := make(http.Header)
			switch r.URL.Path {
			case "/start":
				hdr.Set("Location", "https://other.example.com/hop")
				return &http.Response{StatusCode: http.StatusFound, Header: hdr, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			case "/hop":
				hdr.Set("Location", "https://[0:0:0:0:0:0:0:1]:443/final")
				return &http.Response{StatusCode: http.StatusFound, Header: hdr, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			default:
				bounceAuth = r.Header.Get("Authorization")
				return &http.Response{StatusCode: http.StatusOK, Header: hdr, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
			}
		})
		bounceClient := newHTTPClient(5*time.Second, false)
		bounceClient.Transport = bounceRT
		stBounce, _, err := getJSON(context.Background(), bounceClient, "https://[::1]/start", "secret-bearer-token")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, stBounce)
		assert.Empty(t, bounceAuth, "Authorization must stay stripped after an intermediate cross-origin redirect")

		// Redirect rejection errors (cross-origin, https->http downgrade, and
		// redirect-limit failures) and resolveUsername logs must redact URL
		// userinfo credentials and query/fragment tokens from Location headers.
		joinSecretURL := func(parts ...string) string { return strings.Join(parts, "") }
		secretRedirectCases := []struct {
			name     string
			insecure bool
			location string
			wantErr  string
			secrets  []string
		}{
			{
				name:     "cross-origin redirect error redacts userinfo and query token",
				insecure: true,
				location: joinSecretURL("https://", "admin", ":", "CrossOriginPass777", "@evil.example.com:8443/cb?access_token=", "CrossOriginTok777", "#frag=", "CrossFrag777"),
				wantErr:  "insecureSkipTlsVerify",
				secrets:  []string{"CrossOriginPass777", "CrossOriginTok777", "CrossFrag777"},
			},
			{
				name:     "scheme downgrade redirect error redacts userinfo and query token",
				insecure: false,
				location: joinSecretURL("http://", "alice", ":", "DowngradePass888", "@api.example.com/cb?access_token=", "DowngradeTok888"),
				wantErr:  "refusing redirect from https to http",
				secrets:  []string{"DowngradePass888", "DowngradeTok888"},
			},
			{
				name:     "redirect limit error redacts userinfo and query token",
				insecure: false,
				location: joinSecretURL("https://", "bob", ":", "LoopPass999", "@api.example.com/loop?access_token=", "LoopTok999"),
				wantErr:  "stopped after 10 redirects",
				secrets:  []string{"LoopPass999", "LoopTok999"},
			},
			{
				name:     "quoted Location parse error with embedded quotes redacts userinfo and query token",
				insecure: false,
				location: joinSecretURL("https://", "carol", ":", "QuotePass111", "@evil.example.com/cb%ZZ?q=\"x\"&access_token=", "QuoteTok111", "#frag=", "QuoteFrag111"),
				wantErr:  "failed to parse Location header",
				secrets:  []string{"QuotePass111", "QuoteTok111", "QuoteFrag111"},
			},
			{
				name:     "malformed relative Location parse error redacts query and fragment tokens",
				insecure: false,
				location: joinSecretURL("/callback%ZZ?access_token=", "RelQueryTok222", "#frag=", "RelFragTok222"),
				wantErr:  "failed to parse Location header",
				secrets:  []string{"RelQueryTok222", "RelFragTok222"},
			},
			{
				name:     "malformed scheme-relative Location parse error redacts userinfo and query token",
				insecure: false,
				location: joinSecretURL("//", "dave", ":", "SchemeRelPass333", "@evil.example.com/cb%ZZ?access_token=", "SchemeRelTok333"),
				wantErr:  "failed to parse Location header",
				secrets:  []string{"SchemeRelPass333", "SchemeRelTok333"},
			},
		}
		for _, sc := range secretRedirectCases {
			t.Run(sc.name, func(t *testing.T) {
				rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
					hdr := make(http.Header)
					hdr.Set("Location", sc.location)
					return &http.Response{
						StatusCode: http.StatusFound,
						Header:     hdr,
						Body:       io.NopCloser(strings.NewReader("")),
						Request:    r,
					}, nil
				})
				c := newHTTPClient(5*time.Second, sc.insecure)
				c.Transport = rt

				_, _, rerr := getJSON(context.Background(), c, "https://api.example.com/start", "bearer-tok")
				require.Error(t, rerr)
				assert.Contains(t, rerr.Error(), sc.wantErr)
				for _, sec := range sc.secrets {
					assert.NotContains(t, rerr.Error(), sec)
				}

				var logs []string
				var logMu sync.Mutex
				lgr := funcr.New(func(prefix, args string) {
					logMu.Lock()
					logs = append(logs, prefix+args)
					logMu.Unlock()
				}, funcr.Options{})
				_ = resolveUsername(logr.NewContext(context.Background(), lgr), c, "https://api.example.com", "bearer-tok")
				logMu.Lock()
				combinedLogs := strings.Join(logs, "\n")
				logMu.Unlock()
				for _, sec := range sc.secrets {
					assert.NotContains(t, combinedLogs, sec, "resolveUsername log must redact redirect credentials")
				}
			})
		}

		// Transport/TLS errors containing unmatched double quotes (both raw and
		// inside recursively unquoted %q spans) must terminate immediately and
		// redact embedded credential-bearing URLs.
		rawUnmatched := fmt.Errorf("tls handshake \"unterminated %s", joinSecretURL("https://", "eve", ":", "RawUnmatchedPass444", "@evil.example.com/cb?access_token=", "RawUnmatchedTok444"))
		nestedUnmatched := fmt.Errorf("outer %q", fmt.Sprintf("detail \"unterminated %s", joinSecretURL("https://", "frank", ":", "RecUnmatchedPass555", "@evil.example.com/cb?access_token=", "RecUnmatchedTok555")))
		quotedSpacePassword := fmt.Errorf("parse %q: invalid URL", joinSecretURL("https://", "grace", ":", "SpaceLeft666 SpaceRight666", "@evil.example.com"))
		for _, uq := range []struct {
			name    string
			err     error
			secrets []string
		}{
			{
				name:    "raw unmatched double quote in transport error",
				err:     rawUnmatched,
				secrets: []string{"RawUnmatchedPass444", "RawUnmatchedTok444"},
			},
			{
				name:    "recursively unquoted unmatched double quote in transport error",
				err:     nestedUnmatched,
				secrets: []string{"RecUnmatchedPass555", "RecUnmatchedTok555"},
			},
			{
				name:    "quoted URL with space inside userinfo password",
				err:     quotedSpacePassword,
				secrets: []string{"SpaceLeft666", "SpaceRight666"},
			},
		} {
			t.Run(uq.name, func(t *testing.T) {
				rt := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return nil, uq.err
				})
				c := newHTTPClient(5*time.Second, false)
				c.Transport = rt
				_, _, uerr := getJSON(context.Background(), c, "https://api.example.com/start", "bearer-tok")
				require.Error(t, uerr)
				for _, sec := range uq.secrets {
					assert.NotContains(t, uerr.Error(), sec)
				}
			})
		}
	})

	t.Run("malformed GetToken scopes fail closed without leaking held user token", func(t *testing.T) {
		cs := newClusterServer(t)
		p := newWiredPlugin(t, cs, fakeBrowser("admin-user-token", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)

		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)

		for _, badScope := range []string{
			" ",
			"\t",
			"\n",
			" \t\n ",
			"\u00a0",
			"infra-auto/",
			"/pipeline",
			"a/b/c",
			"system:serviceaccount:ns-only",
			"infra-auto/pipeline@",
			"infra-auto/pipeline extra",
			"arbitrary-unknown-scope",
		} {
			_, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: badScope})
			require.Error(t, err, "scope %q must fail closed", badScope)
		}

		// Explicit "user" and "user:full" scopes return the held user token.
		for _, okScope := range []string{"", "user", "user:full"} {
			tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: okScope})
			require.NoError(t, err)
			assert.Equal(t, "admin-user-token", tok.AccessToken)
		}
	})

	t.Run("TokenRequest error body and whoami username strip terminal control chars and slice UTF-8 safely", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/token") {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("denied\x1b[31mSPOOF\u202e-" + strings.Repeat("\xe2\x9c\x93", 200)))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"metadata":{"name":"alice\u001b[31m\u202e"}}`))
		}))
		defer srv.Close()

		name := resolveUsername(context.Background(), srv.Client(), srv.URL, "tok")
		assert.Equal(t, "alice31m", strings.ReplaceAll(name, "[", ""))
		assert.NotContains(t, name, "\x1b")
		assert.NotContains(t, name, "\u202e")

		_, err := mintServiceAccountToken(context.Background(), srv.Client(), mintSAParams{
			APIServerURL:   srv.URL,
			BearerToken:    "tok",
			Namespace:      "default",
			ServiceAccount: "builder",
		})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "\x1b")
		assert.NotContains(t, err.Error(), "\u202e")
	})
}

func TestBlueprintCallbackPagesAndDeferredCompletion(t *testing.T) {
	const (
		customSuccess = "<!doctype html><html><body>OPENSHIFT-BLUEPRINT-SUCCESS</body></html>"
		customFailure = "<!doctype html><html><body>OPENSHIFT-BLUEPRINT-FAILURE</body></html>"
	)

	newBlueprintPlugin := func(t *testing.T, cs *clusterServer, browser browserOpener) *Plugin {
		t.Helper()
		p := &Plugin{
			http:    cs.srv.Client(),
			browser: browser,
		}
		cfg := mustSettings(t, cs.url())
		cfg.AuthCallbackPages = &sdkplugin.AuthCallbackPages{
			SuccessHTML: []byte(customSuccess),
			FailureHTML: []byte(customFailure),
		}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, cfg))
		p.config.LoginTimeout = 3 * time.Second
		return p
	}

	t.Run("holds browser response until whoami and credential storage succeed", func(t *testing.T) {
		cs := newClusterServer(t)
		whoamiEntered := make(chan struct{})
		releaseWhoami := make(chan struct{})
		var once sync.Once
		cs.whoamiHook = func() {
			once.Do(func() {
				close(whoamiEntered)
				<-releaseWhoami
			})
		}

		type browserOutcome struct {
			bridgeStatus int
			bridgeCSP    string
			postStatus   int
			postBody     string
			postCSP      string
			err          error
		}
		outCh := make(chan browserOutcome, 1)

		browser := func(ctx context.Context, rawURL string) error {
			u, err := url.Parse(rawURL)
			if err != nil {
				return err
			}
			redirect := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			cbParsed, err := url.Parse(redirect)
			if err != nil {
				return err
			}
			origin := cbParsed.Scheme + "://" + cbParsed.Host
			reqCtx := context.WithoutCancel(ctx)

			go func() {
				getReq, getReqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, redirect, nil)
				if getReqErr != nil {
					outCh <- browserOutcome{err: getReqErr}
					return
				}
				bridgeResp, getErr := http.DefaultClient.Do(getReq)
				if getErr != nil {
					outCh <- browserOutcome{err: getErr}
					return
				}
				bridgeCSP := bridgeResp.Header.Get("Content-Security-Policy")
				bridgeStatus := bridgeResp.StatusCode
				_ = bridgeResp.Body.Close()

				form := url.Values{
					"access_token": {"deferred-tok"},
					"token_type":   {"Bearer"},
					"expires_in":   {"3600"},
					"state":        {state},
				}
				req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, origin+"/token", strings.NewReader(form.Encode()))
				if reqErr != nil {
					outCh <- browserOutcome{err: reqErr}
					return
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", origin)

				postResp, postErr := http.DefaultClient.Do(req)
				if postErr != nil {
					outCh <- browserOutcome{err: postErr}
					return
				}
				defer func() { _ = postResp.Body.Close() }()
				b, readErr := io.ReadAll(postResp.Body)
				outCh <- browserOutcome{
					bridgeStatus: bridgeStatus,
					bridgeCSP:    bridgeCSP,
					postStatus:   postResp.StatusCode,
					postBody:     string(b),
					postCSP:      postResp.Header.Get("Content-Security-Policy"),
					err:          readErr,
				}
			}()
			return nil
		}

		p := newBlueprintPlugin(t, cs, browser)
		fake := newFakeHostService()
		loginDone := make(chan error, 1)
		go func() {
			_, lerr := p.Login(hostContext(fake), HandlerName, sdkplugin.LoginRequest{}, nil)
			loginDone <- lerr
		}()

		<-whoamiEntered

		// While whoami + SetSecret are still pending, the browser POST must NOT have settled yet.
		select {
		case premature := <-outCh:
			t.Fatalf("browser received premature response before commit completed: %+v", premature)
		case <-time.After(60 * time.Millisecond):
		}

		close(releaseWhoami)
		require.NoError(t, <-loginDone)

		out := <-outCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.bridgeStatus)
		assert.Contains(t, out.bridgeCSP, "script-src 'sha256-")
		assert.Equal(t, http.StatusOK, out.postStatus)
		assert.Equal(t, customSuccess, out.postBody)
		assert.Contains(t, out.postCSP, "default-src 'none'")
	})

	t.Run("secret store failure serves 503 custom FailureHTML instead of SuccessHTML", func(t *testing.T) {
		cs := newClusterServer(t)

		type postOutcome struct {
			status int
			body   string
			err    error
		}
		outCh := make(chan postOutcome, 1)

		browser := func(ctx context.Context, rawURL string) error {
			u, err := url.Parse(rawURL)
			if err != nil {
				return err
			}
			redirect := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			cbParsed, _ := url.Parse(redirect)
			origin := cbParsed.Scheme + "://" + cbParsed.Host
			reqCtx := context.WithoutCancel(ctx)

			go func() {
				form := url.Values{
					"access_token": {"unpersisted-tok"},
					"token_type":   {"Bearer"},
					"state":        {state},
				}
				req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, origin+"/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", origin)
				resp, postErr := http.DefaultClient.Do(req)
				if postErr != nil {
					outCh <- postOutcome{err: postErr}
					return
				}
				defer func() { _ = resp.Body.Close() }()
				b, readErr := io.ReadAll(resp.Body)
				outCh <- postOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		p := newBlueprintPlugin(t, cs, browser)
		fake := newFakeHostService()
		fake.setWriteError(errors.New("keyring locked"))

		_, err := p.Login(hostContext(fake), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "persist token")

		out := <-outCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, customFailure, out.body)
		assert.NotContains(t, out.body, "OPENSHIFT-BLUEPRINT-SUCCESS")
	})

	t.Run("direct OAuth error serves 400 custom FailureHTML without leaking error_description and sanitizes terminal error", func(t *testing.T) {
		cs := newClusterServer(t)

		type postOutcome struct {
			status int
			body   string
			err    error
		}
		outCh := make(chan postOutcome, 1)

		browser := func(ctx context.Context, rawURL string) error {
			u, err := url.Parse(rawURL)
			if err != nil {
				return err
			}
			redirect := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			cbParsed, _ := url.Parse(redirect)
			origin := cbParsed.Scheme + "://" + cbParsed.Host
			reqCtx := context.WithoutCancel(ctx)

			go func() {
				form := url.Values{
					"error":             {"access_denied"},
					"error_description": {"sensitive-idp-detail\x1b[31mSPOOF"},
					"state":             {state},
				}
				req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, origin+"/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", origin)
				resp, postErr := http.DefaultClient.Do(req)
				if postErr != nil {
					outCh <- postOutcome{err: postErr}
					return
				}
				defer func() { _ = resp.Body.Close() }()
				b, readErr := io.ReadAll(resp.Body)
				outCh <- postOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		p := newBlueprintPlugin(t, cs, browser)
		_, err := p.Login(hostContext(newFakeHostService()), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
		assert.NotContains(t, err.Error(), "\x1b", "terminal escape codes must be stripped")

		out := <-outCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusBadRequest, out.status)
		assert.Equal(t, customFailure, out.body)
		assert.NotContains(t, out.body, "sensitive-idp-detail")
	})
}

func TestBrowserPreferenceForwarding(t *testing.T) {
	cs := newClusterServer(t)

	t.Run("Login forwards req.Browser and LoginTimeout deadline into browserOpener context", func(t *testing.T) {
		var gotBrowser string
		var hasDeadline bool
		inner := fakeBrowser("tok", 3600)
		capturing := func(ctx context.Context, rawURL string) error {
			gotBrowser = browserPreferenceFromContext(ctx)
			_, hasDeadline = ctx.Deadline()
			return inner(ctx, rawURL)
		}

		p := newWiredPlugin(t, cs, capturing)
		_, err := p.Login(hostContext(newFakeHostService()), HandlerName, sdkplugin.LoginRequest{
			Browser: "msedge",
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "msedge", gotBrowser)
		assert.True(t, hasDeadline, "OpenBrowser context must carry LoginTimeout deadline")
	})

	t.Run("defaultBrowserOpener honors cancelled ctx, rejects invalid URLs, and wires warning handler", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		err := defaultBrowserOpener(withBrowserPreference(canceledCtx, "firefox"), "https://oauth.example.com/authorize")
		require.Error(t, err)

		// Non-http scheme rejected before spawning any process.
		err = defaultBrowserOpener(context.Background(), "javascript:alert(1)")
		require.Error(t, err)

		// Verify warning handler wiring when an explicit nonexistent browser
		// preference fails before attempting system fallback.
		t.Setenv("PATH", t.TempDir())
		t.Setenv("BROWSER", "")
		t.Setenv("WSL_DISTRO_NAME", "")
		t.Setenv("WSL_INTEROP", "")
		var logged []string
		var logMu sync.Mutex
		lgr := funcr.New(func(prefix, args string) {
			logMu.Lock()
			logged = append(logged, prefix+args)
			logMu.Unlock()
		}, funcr.Options{})
		warnCtx := logr.NewContext(context.Background(), lgr)
		_ = defaultBrowserOpener(withBrowserPreference(warnCtx, "nonexistent-browser-binary-xyz"), "https://oauth.example.com/authorize")

		logMu.Lock()
		joined := strings.Join(logged, "\n")
		logMu.Unlock()
		assert.Contains(t, joined, "nonexistent-browser-binary-xyz")
	})
}

func TestStatelessPerRPCSettingsAndProfileIsolationRace(t *testing.T) {
	baseCluster := newClusterServer(t)
	baseCluster.whoamiName = "base-user"

	workCluster := newClusterServer(t)
	workCluster.whoamiName = "work-user"

	sandboxCluster := newClusterServer(t)
	sandboxCluster.whoamiName = "sandbox-user"

	var clientIDsMu sync.Mutex
	seenClientIDs := map[string]string{}

	browser := func(ctx context.Context, rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		origin := u.Scheme + "://" + u.Host
		clientIDsMu.Lock()
		seenClientIDs[origin] = u.Query().Get("client_id")
		clientIDsMu.Unlock()

		var tok string
		switch origin {
		case baseCluster.url():
			tok = "tok-base"
		case workCluster.url():
			tok = "tok-work"
		case sandboxCluster.url():
			tok = "tok-sandbox"
		default:
			return fmt.Errorf("unexpected origin %s", origin)
		}
		return fakeBrowser(tok, 3600)(ctx, rawURL)
	}

	p := &Plugin{browser: browser}
	require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		Settings: map[string]json.RawMessage{
			HandlerName: json.RawMessage(fmt.Sprintf(`{"apiServerUrl":%q,"oauthClientId":"base-client","loginTimeout":"3s"}`, baseCluster.url())),
		},
	}))

	fake := newFakeHostService()

	// Exercise "clientId" ApplyOverrides key and cold concurrent httpClientForConfig creation.
	workSettings := map[string]json.RawMessage{
		HandlerName: json.RawMessage(fmt.Sprintf(`{"clientId":"work-override-client","loginTimeout":"3s","insecureSkipTlsVerify":false,"clusters":{"target":{"url":%q}}}`, workCluster.url())),
	}
	sandboxSettings := map[string]json.RawMessage{
		"apiServerUrl":          json.RawMessage(fmt.Sprintf("%q", sandboxCluster.url())),
		"oauthClientId":         json.RawMessage(`"sandbox-client"`),
		"loginTimeout":          json.RawMessage(`"3s"`),
		"insecureSkipTlsVerify": json.RawMessage(`true`),
	}

	// Stress cold httpClientForConfig under concurrent goroutines before any client is cached.
	var coldWG sync.WaitGroup
	for i := 0; i < 16; i++ {
		coldWG.Add(2)
		go func() {
			defer coldWG.Done()
			_ = p.httpClientForConfig(&Config{InsecureSkipTLSVerify: false})
		}()
		go func() {
			defer coldWG.Done()
			_ = p.httpClientForConfig(&Config{InsecureSkipTLSVerify: true})
		}()
	}
	coldWG.Wait()

	stdC1 := p.httpClientForConfig(&Config{InsecureSkipTLSVerify: false})
	stdC2 := p.httpClientForConfig(&Config{InsecureSkipTLSVerify: false})
	insC1 := p.httpClientForConfig(&Config{InsecureSkipTLSVerify: true})
	insC2 := p.httpClientForConfig(&Config{InsecureSkipTLSVerify: true})
	assert.Same(t, stdC1, stdC2, "secure HTTP client must be reused")
	assert.Same(t, insC1, insC2, "insecure HTTP client must be reused")
	assert.NotSame(t, stdC1, insC1, "secure and insecure HTTP clients must be distinct")

	workCtx := sdkplugin.WithRequestSettings(auth.WithProfile(hostContext(fake), "work"), workSettings)
	sandboxCtx := auth.WithProfile(hostContext(fake), "sandbox")

	_, err := p.Login(workCtx, HandlerName, sdkplugin.LoginRequest{Hostname: "target"}, nil)
	require.NoError(t, err)

	_, err = p.Login(sandboxCtx, HandlerName, sdkplugin.LoginRequest{Settings: sandboxSettings}, nil)
	require.NoError(t, err)

	clientIDsMu.Lock()
	assert.Equal(t, "work-override-client", seenClientIDs[workCluster.url()])
	assert.Equal(t, "sandbox-client", seenClientIDs[sandboxCluster.url()])
	clientIDsMu.Unlock()

	// Concurrent reads and SA ForceRefresh mints across profiles under -race.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			tok, gerr := p.GetToken(workCtx, HandlerName, sdkplugin.TokenRequest{Hostname: "target"})
			if assert.NoError(t, gerr) {
				assert.Equal(t, "tok-work", tok.AccessToken)
			}
			saTok, serr := p.GetToken(workCtx, HandlerName, sdkplugin.TokenRequest{
				Hostname:     "target",
				Scope:        "default/builder",
				ForceRefresh: true,
			})
			if assert.NoError(t, serr) {
				assert.Equal(t, "sa-minted-token", saTok.AccessToken)
			}
		}()
		go func() {
			defer wg.Done()
			tok, gerr := p.GetToken(sandboxCtx, HandlerName, sdkplugin.TokenRequest{Settings: sandboxSettings})
			if assert.NoError(t, gerr) {
				assert.Equal(t, "tok-sandbox", tok.AccessToken)
			}
			st, serr := p.GetStatus(sandboxCtx, HandlerName, sdkplugin.StatusRequest{Settings: sandboxSettings})
			if assert.NoError(t, serr) {
				assert.True(t, st.Authenticated)
				assert.Equal(t, "sandbox-user", st.Claims.Username)
			}
		}()
		go func() {
			defer wg.Done()
			st, serr := p.GetStatus(hostContext(fake), HandlerName, sdkplugin.StatusRequest{})
			if assert.NoError(t, serr) {
				assert.False(t, st.Authenticated)
			}
			flows, ferr := p.DetectAvailableFlows(workCtx, HandlerName)
			if assert.NoError(t, ferr) {
				assert.Len(t, flows, 1)
			}
		}()
	}
	wg.Wait()

	// Base p.config must remain completely untouched, and ApplyOverrides re-ConfigureAuthHandler preserves pooled clients.
	assert.Equal(t, baseCluster.url(), p.config.APIServerURL)
	assert.Equal(t, "base-client", p.config.OAuthClientID)
	assert.False(t, p.config.InsecureSkipTLSVerify)
	require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		Settings: map[string]json.RawMessage{
			HandlerName: json.RawMessage(fmt.Sprintf(`{"apiServerUrl":%q,"clientId":"override-2"}`, baseCluster.url())),
		},
	}))
	assert.Same(t, stdC1, p.httpClientForConfig(&Config{InsecureSkipTLSVerify: false}), "ConfigureAuthHandler must preserve pooled HTTP transport")

	// Empty per-RPC RequestSettings for a profile with no settings must NOT
	// inherit p.config's baseCluster APIServerURL.
	cleanProfileCtx := sdkplugin.WithRequestSettings(auth.WithProfile(hostContext(fake), "clean"), map[string]json.RawMessage{})
	cleanCfg, err := p.effectiveConfig(cleanProfileCtx, 0)
	require.NoError(t, err)
	assert.Empty(t, cleanCfg.APIServerURL)

	// Invalid per-RPC settings (privileged callbackPort or non-loopback callbackHost) are rejected across methods.
	for _, rawBad := range []string{`{"callbackPort":80}`, `{"callbackHost":"0.0.0.0"}`} {
		badCtx := sdkplugin.WithRequestSettings(hostContext(fake), map[string]json.RawMessage{
			HandlerName: json.RawMessage(rawBad),
		})
		_, err = p.Login(badCtx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.Error(t, err)
		_, err = p.GetToken(badCtx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		_, err = p.GetStatus(badCtx, HandlerName, sdkplugin.StatusRequest{})
		require.Error(t, err)
		_, err = p.DetectAvailableFlows(badCtx, HandlerName)
		require.Error(t, err)
		require.Error(t, p.Logout(badCtx, HandlerName, sdkplugin.LogoutRequest{}))
	}

	// Bracketed IPv6 "[::1]" normalizes to "::1", while unsupported "127.0.0.5" is rejected by oauth-helpers allowlist.
	cIPv6 := DefaultConfig()
	require.NoError(t, cIPv6.applySettings(map[string]json.RawMessage{
		HandlerName: json.RawMessage(`{"callbackHost":"[::1]"}`),
	}))
	assert.Equal(t, "::1", cIPv6.CallbackHost)
	_, err = startImplicitCallback(context.Background(), "127.0.0.5", 0, "st", nil)
	require.Error(t, err)

	require.Error(t, p.StopAuthHandler(context.Background(), "other"))
	require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))
}

// fakeLoginStream captures server-streamed LoginStreamMessage frames from
// sdkplugin.AuthHandlerGRPCServer.Login.
type fakeLoginStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*proto.LoginStreamMessage
}

func (s *fakeLoginStream) Context() context.Context { return s.ctx }

func (s *fakeLoginStream) Send(m *proto.LoginStreamMessage) error {
	s.msgs = append(s.msgs, m)
	return nil
}

func (s *fakeLoginStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeLoginStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeLoginStream) SetTrailer(metadata.MD)       {}

func TestGRPCAuthHandlerServerRoundTrip(t *testing.T) {
	clusterA := newClusterServer(t)
	clusterA.whoamiName = "grpc-alice"

	clusterB := newClusterServer(t)
	clusterB.whoamiName = "grpc-bob"

	p := &Plugin{
		http: http.DefaultClient,
		browser: func(ctx context.Context, rawURL string) error {
			u, _ := url.Parse(rawURL)
			origin := u.Scheme + "://" + u.Host
			if origin == clusterA.url() {
				// Omit expires_in (0) on cluster A to verify non-zero Unix expiry synthesis over gRPC.
				return fakeBrowser("grpc-tok-a", 0)(ctx, rawURL)
			}
			return fakeBrowser("grpc-tok-b", 3600)(ctx, rawURL)
		},
	}

	srv := &sdkplugin.AuthHandlerGRPCServer{Impl: p}
	fake := newFakeHostService()
	baseCtx := hostContext(fake)

	infoResp, err := srv.GetAuthHandlers(baseCtx, &proto.GetAuthHandlersRequest{})
	require.NoError(t, err)
	require.Len(t, infoResp.Handlers, 1)
	assert.Contains(t, infoResp.Handlers[0].Capabilities, string(auth.CapHostname))
	assert.Contains(t, infoResp.Handlers[0].Capabilities, string(auth.CapTokenHostname))

	cfgResp, err := srv.ConfigureAuthHandler(baseCtx, &proto.ConfigureAuthHandlerRequest{
		HandlerName: HandlerName,
		BinaryName:  "mycli",
		Settings: map[string][]byte{
			HandlerName: []byte(`{"loginTimeout":"3s"}`),
		},
		AuthCallbackPages: &proto.AuthCallbackPages{
			SuccessHtml: []byte("<!doctype html><html><body>OK</body></html>"),
			FailureHtml: []byte("<!doctype html><html><body>ERR</body></html>"),
		},
	})
	require.NoError(t, err)
	assert.Empty(t, cfgResp.Error)

	perCallSettings := []byte(fmt.Sprintf(`{"openshift":{"loginTimeout":"3s","clusters":{"a":{"url":%q},"b":{"url":%q}}}}`, clusterA.url(), clusterB.url()))

	flowsResp, err := srv.DetectAvailableFlows(baseCtx, &proto.DetectAvailableFlowsRequest{
		HandlerName: HandlerName,
		Profile:     "ops",
		Settings:    perCallSettings,
	})
	require.NoError(t, err)
	assert.Empty(t, flowsResp.Error)
	require.Len(t, flowsResp.Flows, 1)

	for _, alias := range []string{"a", "b"} {
		stream := &fakeLoginStream{ctx: baseCtx}
		require.NoError(t, srv.Login(&proto.LoginRequest{
			HandlerName: HandlerName,
			Profile:     "ops",
			Hostname:    alias,
			Browser:     "chrome",
			Settings:    perCallSettings,
		}, stream))
		require.Len(t, stream.msgs, 1)
		require.NotNil(t, stream.msgs[0].GetResult(), "unexpected error: %s", stream.msgs[0].GetError())
		assert.Greater(t, stream.msgs[0].GetResult().ExpiresAtUnix, time.Now().Unix(), "LoginResult.ExpiresAtUnix must never be <= 0")
	}

	tokAResp, err := srv.GetToken(baseCtx, &proto.GetTokenRequest{
		HandlerName: HandlerName,
		Profile:     "ops",
		Hostname:    clusterA.url(),
		Settings:    perCallSettings,
	})
	require.NoError(t, err)
	assert.Equal(t, "grpc-tok-a", tokAResp.AccessToken)
	assert.Greater(t, tokAResp.ExpiresAtUnix, time.Now().Unix(), "GetTokenResponse.ExpiresAtUnix must never serialize zero as 1970-01-01")

	tokBResp, err := srv.GetToken(baseCtx, &proto.GetTokenRequest{
		HandlerName: HandlerName,
		Profile:     "ops",
		Hostname:    clusterB.url(),
		Settings:    perCallSettings,
	})
	require.NoError(t, err)
	assert.Equal(t, "grpc-tok-b", tokBResp.AccessToken)

	listResp, err := srv.ListCachedTokens(baseCtx, &proto.ListCachedTokensRequest{
		HandlerName: HandlerName,
		Profile:     "ops",
	})
	require.NoError(t, err)
	assert.Len(t, listResp.Tokens, 2)

	purgeResp, err := srv.PurgeExpiredTokens(baseCtx, &proto.PurgeExpiredTokensRequest{
		HandlerName: HandlerName,
		Profile:     "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, int32(0), purgeResp.PurgedCount)

	_, err = srv.Logout(baseCtx, &proto.LogoutRequest{
		HandlerName: HandlerName,
		Profile:     "ops",
		Hostname:    clusterB.url(),
	})
	require.NoError(t, err)

	// After logging out of active cluster B, status with empty Hostname promotes live cluster A.
	stResp, err := srv.GetStatus(baseCtx, &proto.GetStatusRequest{
		HandlerName: HandlerName,
		Profile:     "ops",
		Settings:    perCallSettings,
	})
	require.NoError(t, err)
	assert.True(t, stResp.Authenticated)
	assert.Equal(t, "grpc-alice", stResp.Claims.Username)

	stopResp, err := srv.StopAuthHandler(baseCtx, &proto.StopAuthHandlerRequest{HandlerName: HandlerName})
	require.NoError(t, err)
	assert.Empty(t, stopResp.Error)
}

func TestSessionLifecycleInvariantsAndEdgeCases(t *testing.T) {
	t.Run("re-Login invalidates prior user's cached SA tokens and ABA re-Login during SA mint prevents caching stale SA token", func(t *testing.T) {
		cs := newClusterServer(t)
		cs.saToken = "admin-sa-token"

		currentUserToken := "user-a-token"
		p := newWiredPlugin(t, cs, func(ctx context.Context, rawURL string) error {
			return fakeBrowser(currentUserToken, 3600)(ctx, rawURL)
		})
		fake := newFakeHostService()
		ctx := hostContext(fake)

		// User A logs in and mints an SA token.
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		sa1, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "kube-system/admin-sa"})
		require.NoError(t, err)
		assert.Equal(t, "admin-sa-token", sa1.AccessToken)

		// User B logs in on the same cluster/profile without an intermediate Logout;
		// User A's cached SA token must be purged so User B must re-mint via RBAC.
		currentUserToken = "user-b-token"
		cs.mu.Lock()
		cs.saToken = "user-b-sa-token"
		cs.mu.Unlock()
		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)

		sa2, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "kube-system/admin-sa"})
		require.NoError(t, err)
		assert.Equal(t, "user-b-sa-token", sa2.AccessToken, "re-Login must invalidate prior user session's cached SA tokens")

		// Now test concurrent ABA swap: User B starts minting a fresh SA token;
		// while HTTP TokenRequest is in flight, User C logs in. User B's in-flight
		// SA token must NOT be cached over User C's session.
		saEntered := make(chan struct{})
		releaseSA := make(chan struct{})
		var once sync.Once
		cs.mu.Lock()
		cs.saToken = "stale-user-b-mint"
		cs.saHook = func() {
			once.Do(func() {
				close(saEntered)
				<-releaseSA
			})
		}
		cs.mu.Unlock()

		mintDone := make(chan error, 1)
		go func() {
			_, merr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "ns2/sa2"})
			mintDone <- merr
		}()

		<-saEntered
		currentUserToken = "user-c-token"
		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)

		close(releaseSA)
		require.Error(t, <-mintDone, "GetToken must fail when user session was replaced during in-flight SA mint")

		cs.mu.Lock()
		cs.saHook = nil
		cs.saToken = "fresh-user-c-mint"
		cs.mu.Unlock()

		saC, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "ns2/sa2"})
		require.NoError(t, err)
		assert.Equal(t, "fresh-user-c-mint", saC.AccessToken, "ABA re-Login during in-flight SA mint must not cache prior user's SA token")

		// Concurrent Logout while SA mint is in flight must also fail GetToken
		// rather than returning a token for a logged-out session.
		logoutSAEntered := make(chan struct{})
		releaseLogoutSA := make(chan struct{})
		var logoutOnce sync.Once
		cs.mu.Lock()
		cs.saToken = "logged-out-sa-mint"
		cs.saHook = func() {
			logoutOnce.Do(func() {
				close(logoutSAEntered)
				<-releaseLogoutSA
			})
		}
		cs.mu.Unlock()

		type saResult struct {
			resp *sdkplugin.TokenResponse
			err  error
		}
		logoutMintDone := make(chan saResult, 1)
		go func() {
			resp, merr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "ns3/sa3"})
			logoutMintDone <- saResult{resp: resp, err: merr}
		}()

		<-logoutSAEntered
		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
		close(releaseLogoutSA)

		logoutRes := <-logoutMintDone
		require.Error(t, logoutRes.err, "GetToken must fail when session was logged out during in-flight SA mint")
		assert.Nil(t, logoutRes.resp)
		cs.mu.Lock()
		cs.saHook = nil
		cs.mu.Unlock()

		// Concurrent Logout followed by re-Login with the SAME user bearer token
		// while SA mint is in flight must also reject the pre-logout SA mint via
		// CachedAt session comparison rather than caching or returning it.
		currentUserToken = "same-bearer-token-across-relogin"
		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)

		sameBearerEntered := make(chan struct{})
		releaseSameBearer := make(chan struct{})
		var sameBearerOnce sync.Once
		cs.mu.Lock()
		cs.saToken = "stale-pre-logout-same-bearer-sa"
		cs.saHook = func() {
			sameBearerOnce.Do(func() {
				close(sameBearerEntered)
				<-releaseSameBearer
			})
		}
		cs.mu.Unlock()

		sameBearerMintDone := make(chan saResult, 1)
		go func() {
			resp, merr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "ns4/sa4"})
			sameBearerMintDone <- saResult{resp: resp, err: merr}
		}()

		<-sameBearerEntered
		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		close(releaseSameBearer)

		sameBearerRes := <-sameBearerMintDone
		require.Error(t, sameBearerRes.err, "GetToken must fail when session underwent Logout + Login with same bearer during SA mint")
		assert.Nil(t, sameBearerRes.resp)

		cs.mu.Lock()
		cs.saHook = nil
		cs.saToken = "fresh-post-relogin-same-bearer-sa"
		cs.mu.Unlock()
		freshSameBearerSA, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "ns4/sa4"})
		require.NoError(t, err)
		assert.Equal(t, "fresh-post-relogin-same-bearer-sa", freshSameBearerSA.AccessToken)
	})

	t.Run("per-cluster logout deletes corrupt user token secret and propagates delete errors", func(t *testing.T) {
		cs := newClusterServer(t)
		p := newWiredPlugin(t, cs, fakeBrowser("tok", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)
		host := newFakeHostClient(fake)
		prefix := profileKeyPrefix("")

		key := userTokenKey(prefix, cs.url())
		require.NoError(t, host.SetSecret(ctx, key, "{corrupt-json"))

		st, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{Hostname: cs.url()})
		require.NoError(t, err)
		assert.False(t, st.Authenticated)

		// Delete errors surface from Logout rather than silently reporting success.
		fake.setDeleteError(errors.New("keyring write-protected"))
		require.Error(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: cs.url()}))
		require.Error(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
		fake.setDeleteError(nil)

		// Nil host also errors on Logout.
		pNoHost := &Plugin{}
		require.NoError(t, pNoHost.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))
		require.Error(t, pNoHost.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{}))

		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: cs.url()}))
		_, found, err := host.GetSecret(ctx, key)
		require.NoError(t, err)
		assert.False(t, found, "corrupted user token secret must be deleted by cluster logout")
	})

	t.Run("GetStatus with empty Hostname falls back to live cluster when active cluster expired", func(t *testing.T) {
		clusterA := newClusterServer(t)
		clusterB := newClusterServer(t)
		p := &Plugin{http: http.DefaultClient, browser: fakeBrowser("t", 3600)}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))

		fake := newFakeHostService()
		ctx := hostContext(fake)
		host := newFakeHostClient(fake)
		prefix := profileKeyPrefix("")

		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterA.url()), &cacheEntry{
			AccessToken: "live-a",
			Kind:        kindUser,
			APIServer:   clusterA.url(),
			Username:    "alice",
			ExpiresAt:   time.Now().Add(time.Hour),
		}))
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterB.url()), &cacheEntry{
			AccessToken: "expired-b",
			Kind:        kindUser,
			APIServer:   clusterB.url(),
			Username:    "bob",
			ExpiresAt:   time.Now().Add(-time.Hour),
		}))
		require.NoError(t, setActiveCluster(ctx, host, prefix, clusterB.url()))

		// Even before PurgeExpiredTokens runs, GetStatus{} finds live cluster A.
		st, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, clusterA.url(), st.Hostname)

		// PurgeExpiredTokens deletes expired cluster B and promotes cluster A to active.
		purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
		require.NoError(t, err)
		assert.Equal(t, 1, purged)
		assert.Equal(t, clusterA.url(), getActiveCluster(ctx, host, prefix))
	})

	t.Run("cachedHostClient fallback, numeric loginTimeout, empty alias URL, and deterministic cancel/timeout", func(t *testing.T) {
		cs := newClusterServer(t)
		fake := newFakeHostService()

		p := &Plugin{
			http:    cs.srv.Client(),
			browser: fakeBrowser("cached-hc-tok", 3600),
		}
		cfg := sdkplugin.ProviderConfig{
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(fmt.Sprintf(`{"apiServerUrl":%q,"loginTimeout":3000000000}`, cs.url())),
			},
		}
		require.NoError(t, p.ConfigureAuthHandler(hostContext(fake), HandlerName, cfg))

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "cached-hc-tok", tok.AccessToken)

		c := DefaultConfig()
		require.Error(t, c.applySettings(map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"loginTimeout":"not-a-duration"}`),
		}))
		c2 := &Config{Clusters: map[string]Cluster{"empty": {URL: "   "}}}
		_, _, err = c2.resolveCluster("empty")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty url")

		noopBrowser := func(_ context.Context, _ string) error { return nil }
		pTimeout := newWiredPlugin(t, cs, noopBrowser)
		_, err = pTimeout.Login(hostContext(fake), HandlerName, sdkplugin.LoginRequest{Timeout: 40 * time.Millisecond}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no response from browser")

		// Deterministic cancellation triggered from OpenBrowser once runWebLogin is active.
		cancelCtx, cancel := context.WithCancel(hostContext(fake))
		pCancel := newWiredPlugin(t, cs, func(_ context.Context, _ string) error {
			cancel()
			return nil
		})
		_, err = pCancel.Login(cancelCtx, HandlerName, sdkplugin.LoginRequest{Timeout: 5 * time.Second}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "web login: cancelled")
	})

	t.Run("legacy non-canonical user token keys remain accessible and migrate cleanly per profile", func(t *testing.T) {
		cs := newClusterServer(t)
		cs.saToken = "migrated-sa-token"

		p := &Plugin{
			http:    cs.srv.Client(),
			browser: fakeBrowser("fresh-tok", 3600),
		}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))

		fake := newFakeHostService()
		host := newFakeHostClient(fake)
		workCtx := auth.WithProfile(hostContext(fake), "work")
		otherCtx := auth.WithProfile(hostContext(fake), "other")
		workPrefix := profileKeyPrefix("work")

		// Seed a pre-canonicalization entry keyed by the raw mixed-case URL
		// with trailing slash (and a matching non-canonical active marker).
		legacyURL := strings.ToUpper(cs.url()) + "/"
		legacyKey := workPrefix + kindUser + "." + fingerprintHash(strings.TrimRight(legacyURL, "/"))
		canonicalKey := userTokenKey(workPrefix, cs.url())
		require.NotEqual(t, legacyKey, canonicalKey, "legacy mixed-case key hash must differ from canonical key hash")

		legacyEntry := cacheEntry{
			AccessToken: "legacy-upgraded-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(2 * time.Hour).Round(time.Second),
			CachedAt:    time.Now().Add(-5 * time.Minute).Round(time.Second),
			Flow:        auth.FlowInteractive,
			Kind:        kindUser,
			APIServer:   strings.TrimRight(legacyURL, "/"),
			Username:    "legacy-alice",
		}
		// #nosec G117 -- test fixture serialized for fake secret store
		rawBytes, err := json.Marshal(&legacyEntry)
		require.NoError(t, err)
		require.NoError(t, host.SetSecret(workCtx, legacyKey, string(rawBytes)))
		require.NoError(t, host.SetSecret(workCtx, activeClusterKey(workPrefix), strings.TrimRight(legacyURL, "/")))

		// Other profile must not see work's legacy session.
		otherSt, err := p.GetStatus(otherCtx, HandlerName, sdkplugin.StatusRequest{Hostname: cs.url()})
		require.NoError(t, err)
		assert.False(t, otherSt.Authenticated)

		// GetStatus finds the legacy session via both empty Hostname and canonical URL without side effects.
		st, err := p.GetStatus(workCtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, "legacy-alice", st.Claims.Username)
		assert.Equal(t, cs.url(), st.Hostname)

		// GetToken returns the legacy credential and migrates it to the canonical key, removing the legacy key.
		tok, err := p.GetToken(workCtx, HandlerName, sdkplugin.TokenRequest{Hostname: cs.url()})
		require.NoError(t, err)
		assert.Equal(t, "legacy-upgraded-token", tok.AccessToken)
		assert.True(t, tok.ExpiresAt.Equal(legacyEntry.ExpiresAt))

		_, legacyStillThere, err := host.GetSecret(workCtx, legacyKey)
		require.NoError(t, err)
		assert.False(t, legacyStillThere, "legacy key must be deleted once migrated to canonical key")

		_, canonicalPresent, err := host.GetSecret(workCtx, canonicalKey)
		require.NoError(t, err)
		assert.True(t, canonicalPresent, "canonical key must hold the migrated entry")

		listed, err := p.ListCachedTokens(workCtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, listed, 1, "migration must not leave duplicate sessions in ListCachedTokens")

		// Service-account minting and cached SA lookup both work and migrate when seeded with an unmigrated legacy user key.
		require.NoError(t, host.DeleteSecret(workCtx, canonicalKey))
		require.NoError(t, host.SetSecret(workCtx, legacyKey, string(rawBytes)))
		saTok, err := p.GetToken(workCtx, HandlerName, sdkplugin.TokenRequest{
			Hostname: cs.url(),
			Scope:    "default/deployer",
		})
		require.NoError(t, err)
		assert.Equal(t, "migrated-sa-token", saTok.AccessToken)

		// Re-seed legacy user key while the matching SA token remains cached so
		// GetToken(SA) exercises the legacy-migration + SA cache-hit path without re-minting.
		require.NoError(t, host.DeleteSecret(workCtx, canonicalKey))
		require.NoError(t, host.SetSecret(workCtx, legacyKey, string(rawBytes)))
		cs.mu.Lock()
		cs.saToken = "unexpected-remint-token"
		cs.mu.Unlock()
		saCachedTok, err := p.GetToken(workCtx, HandlerName, sdkplugin.TokenRequest{
			Hostname: cs.url(),
			Scope:    "default/deployer",
		})
		require.NoError(t, err)
		assert.Equal(t, "migrated-sa-token", saCachedTok.AccessToken)
		_, legacyAfterSAHit, err := host.GetSecret(workCtx, legacyKey)
		require.NoError(t, err)
		assert.False(t, legacyAfterSAHit, "SA cache-hit path must also migrate legacy user key")
	})

	t.Run("coexisting canonical and legacy keys select by recency without reviving older credentials", func(t *testing.T) {
		cs := newClusterServer(t)
		cs.saToken = "fresh-bob-sa"

		p := &Plugin{
			http:    cs.srv.Client(),
			browser: fakeBrowser("unused-tok", 3600),
		}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))

		fake := newFakeHostService()
		host := newFakeHostClient(fake)
		ctx := auth.WithProfile(hostContext(fake), "upgrade")
		prefix := profileKeyPrefix("upgrade")

		legacyURL := strings.ToUpper(cs.url())
		legacyKey := prefix + kindUser + "." + fingerprintHash(legacyURL)
		canonicalKey := userTokenKey(prefix, cs.url())
		require.NotEqual(t, legacyKey, canonicalKey)

		marshalEntry := func(e cacheEntry) string {
			t.Helper()
			// #nosec G117 -- test fixture serialized for fake secret store
			b, merr := json.Marshal(&e)
			require.NoError(t, merr)
			return string(b)
		}

		// Case 1: Older canonical credential + newer legacy credential coexist.
		// Lookup, status, list, and migration all select the newer legacy session,
		// persist it under canonicalKey before deleting legacyKey, and clear SA
		// tokens belonging to the superseded canonical session.
		now := time.Now().Round(time.Second)
		olderCanonical := cacheEntry{
			AccessToken: "older-alice-token",
			TokenType:   "Bearer",
			CachedAt:    now.Add(-2 * time.Hour),
			ExpiresAt:   now.Add(4 * time.Hour),
			Flow:        auth.FlowInteractive,
			Kind:        kindUser,
			APIServer:   cs.url(),
			Username:    "alice",
		}
		newerLegacy := cacheEntry{
			AccessToken: "newer-bob-token",
			TokenType:   "Bearer",
			CachedAt:    now.Add(-5 * time.Minute),
			ExpiresAt:   now.Add(2 * time.Hour),
			Flow:        auth.FlowInteractive,
			Kind:        kindUser,
			APIServer:   legacyURL,
			Username:    "bob",
		}
		staleSAKey := saTokenKey(prefix, cs.url(), "default", "deployer", "")
		require.NoError(t, host.SetSecret(ctx, canonicalKey, marshalEntry(olderCanonical)))
		require.NoError(t, host.SetSecret(ctx, legacyKey, marshalEntry(newerLegacy)))
		require.NoError(t, cacheSet(ctx, host, staleSAKey, &cacheEntry{
			AccessToken:     "stale-alice-sa",
			Kind:            kindServiceAccount,
			APIServer:       cs.url(),
			Namespace:       "default",
			ServiceAccount:  "deployer",
			ParentTokenHash: fingerprintHash(olderCanonical.AccessToken),
			ExpiresAt:       now.Add(time.Hour),
		}))
		require.NoError(t, setActiveCluster(ctx, host, prefix, cs.url()))

		stByHost, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{Hostname: cs.url()})
		require.NoError(t, err)
		assert.True(t, stByHost.Authenticated)
		assert.Equal(t, "bob", stByHost.Claims.Username, "newer legacy login must win over older canonical login")

		stDefault, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, stDefault.Authenticated)
		assert.Equal(t, "bob", stDefault.Claims.Username)

		listed, err := p.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, err)
		var userItems []*auth.CachedTokenInfo
		for _, item := range listed {
			if item.TokenKind == kindUser {
				userItems = append(userItems, item)
			}
		}
		require.Len(t, userItems, 1, "coexisting canonical and legacy keys must collapse to one user session")
		assert.True(t, userItems[0].ExpiresAt.Equal(newerLegacy.ExpiresAt))

		// Inject a write failure on canonicalKey: migration must NOT delete legacyKey
		// when persisting the selected session fails.
		fake.setWriteErrorForKey(canonicalKey, errors.New("canonical write blocked"))
		tokDuringWriteFail, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: cs.url()})
		require.NoError(t, err)
		assert.Equal(t, "newer-bob-token", tokDuringWriteFail.AccessToken)
		_, legacyPreserved, err := host.GetSecret(ctx, legacyKey)
		require.NoError(t, err)
		assert.True(t, legacyPreserved, "legacy key must not be deleted before canonical persistence succeeds")
		fake.setWriteErrorForKey(canonicalKey, nil)

		// Once canonical persistence succeeds, canonicalKey stores bob, legacyKey is
		// deleted, and alice's superseded SA token is invalidated.
		tokMigrated, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "newer-bob-token", tokMigrated.AccessToken)

		_, legacyGone, err := host.GetSecret(ctx, legacyKey)
		require.NoError(t, err)
		assert.False(t, legacyGone, "superseded legacy key must be deleted after canonical write succeeds")

		persistedCanon, err := cacheGet(ctx, host, canonicalKey)
		require.NoError(t, err)
		require.NotNil(t, persistedCanon)
		assert.Equal(t, "newer-bob-token", persistedCanon.AccessToken)
		assert.Equal(t, "bob", persistedCanon.Username)

		staleSA, err := cacheGet(ctx, host, staleSAKey)
		require.NoError(t, err)
		assert.Nil(t, staleSA, "migration to newer user session must clear superseded user's SA tokens")

		// Case 2: Newer canonical credential has EXPIRED while an older legacy
		// credential still has remaining TTL. Neither GetStatus (including empty
		// Hostname fallback), GetToken, nor PurgeExpiredTokens may revive the
		// older legacy credential.
		olderUsableLegacy := cacheEntry{
			AccessToken: "older-usable-alice",
			TokenType:   "Bearer",
			CachedAt:    now.Add(-3 * time.Hour),
			ExpiresAt:   now.Add(3 * time.Hour),
			Flow:        auth.FlowInteractive,
			Kind:        kindUser,
			APIServer:   legacyURL,
			Username:    "alice",
		}
		newerExpiredCanonical := cacheEntry{
			AccessToken: "newer-expired-bob",
			TokenType:   "Bearer",
			CachedAt:    now.Add(-10 * time.Minute),
			ExpiresAt:   now.Add(-1 * time.Minute),
			Flow:        auth.FlowInteractive,
			Kind:        kindUser,
			APIServer:   cs.url(),
			Username:    "bob",
		}
		require.NoError(t, host.SetSecret(ctx, legacyKey, marshalEntry(olderUsableLegacy)))
		require.NoError(t, host.SetSecret(ctx, canonicalKey, marshalEntry(newerExpiredCanonical)))
		require.NoError(t, setActiveCluster(ctx, host, prefix, cs.url()))

		stExpHost, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{Hostname: cs.url()})
		require.NoError(t, err)
		assert.False(t, stExpHost.Authenticated)
		assert.Equal(t, "token expired", stExpHost.Reason)

		stExpFallback, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, stExpFallback.Authenticated, "fallback scan must not revive older usable legacy credential")
		assert.Equal(t, "token expired", stExpFallback.Reason)

		listedExp, err := p.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, err)
		require.Len(t, listedExp, 1)
		assert.True(t, listedExp[0].IsExpired)

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: cs.url(), Scope: "default/deployer"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authenticated")

		// Re-seed both to verify PurgeExpiredTokens removes both the expired newer
		// session and the superseded older legacy session without reviving alice.
		require.NoError(t, host.SetSecret(ctx, legacyKey, marshalEntry(olderUsableLegacy)))
		require.NoError(t, host.SetSecret(ctx, canonicalKey, marshalEntry(newerExpiredCanonical)))
		purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
		require.NoError(t, err)
		assert.Equal(t, 2, purged)

		stAfterPurge, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, stAfterPurge.Authenticated)
		assert.Equal(t, "not logged in", stAfterPurge.Reason)

		// Mirror subcase: older usable canonical + newer expired legacy also treats
		// the cluster session as expired without reviving the older canonical token,
		// even if PurgeExpiredTokens encounters a delete error on the superseded key.
		olderUsableCanonical := olderUsableLegacy
		olderUsableCanonical.APIServer = cs.url()
		newerExpiredLegacy := newerExpiredCanonical
		newerExpiredLegacy.APIServer = legacyURL
		require.NoError(t, host.SetSecret(ctx, canonicalKey, marshalEntry(olderUsableCanonical)))
		require.NoError(t, host.SetSecret(ctx, legacyKey, marshalEntry(newerExpiredLegacy)))
		require.NoError(t, setActiveCluster(ctx, host, prefix, cs.url()))

		fake.setDeleteErrorForKey(canonicalKey, errors.New("superseded delete blocked"))
		purgedPartial, err := p.PurgeExpiredTokens(ctx, HandlerName)
		require.Error(t, err)
		assert.Equal(t, 0, purgedPartial, "selected expired key must stay intact when superseded key delete fails")
		fake.setDeleteErrorForKey(canonicalKey, nil)

		stMirror, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, stMirror.Authenticated, "failed superseded delete must not revive older usable canonical token")
		assert.Equal(t, "token expired", stMirror.Reason)

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")

		// Purge-first consolidation: older expired canonical + newer usable legacy +
		// stale SA token counts the eliminated expired canonical session (purged == 1)
		// and clears superseded SA tokens before GetToken ever runs.
		olderExpiredCanonical := olderCanonical
		olderExpiredCanonical.ExpiresAt = now.Add(-20 * time.Minute)
		require.NoError(t, host.SetSecret(ctx, canonicalKey, marshalEntry(olderExpiredCanonical)))
		require.NoError(t, host.SetSecret(ctx, legacyKey, marshalEntry(newerLegacy)))
		require.NoError(t, cacheSet(ctx, host, staleSAKey, &cacheEntry{
			AccessToken:     "stale-alice-sa-2",
			Kind:            kindServiceAccount,
			APIServer:       cs.url(),
			Namespace:       "default",
			ServiceAccount:  "deployer",
			ParentTokenHash: fingerprintHash(olderExpiredCanonical.AccessToken),
			ExpiresAt:       now.Add(time.Hour),
		}))

		purgedConsolidate, err := p.PurgeExpiredTokens(ctx, HandlerName)
		require.NoError(t, err)
		assert.Equal(t, 1, purgedConsolidate, "eliminating expired canonical entry via newer legacy consolidation must increment purged count")
		saAfterConsolidate, err := cacheGet(ctx, host, staleSAKey)
		require.NoError(t, err)
		assert.Nil(t, saAfterConsolidate, "PurgeExpiredTokens consolidation must remove superseded user's SA tokens")

		// Per-cluster Logout must not promote a remaining cluster whose newer session
		// is expired even when an older legacy key on that cluster has remaining TTL.
		csOther := newClusterServer(t)
		require.NoError(t, host.SetSecret(ctx, canonicalKey, marshalEntry(newerExpiredCanonical)))
		require.NoError(t, host.SetSecret(ctx, legacyKey, marshalEntry(olderUsableLegacy)))
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, csOther.url()), &cacheEntry{
			AccessToken: "other-live-tok",
			CachedAt:    now.Add(-1 * time.Minute),
			ExpiresAt:   now.Add(time.Hour),
			Kind:        kindUser,
			APIServer:   csOther.url(),
			Username:    "charlie",
		}))
		require.NoError(t, setActiveCluster(ctx, host, prefix, csOther.url()))

		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: csOther.url()}))
		assert.Empty(t, getActiveCluster(ctx, host, prefix), "Logout must not promote a cluster whose newest session is expired")

		// Partial logout delete failures must remove superseded keys before the
		// authoritative key across both recency orderings and both Logout paths so
		// an older usable credential is never revived when cleanup fails.
		for _, ord := range []struct {
			name          string
			canonEntry    cacheEntry
			legacyEntry   cacheEntry
			supersededKey string
		}{
			{
				name:          "newer expired canonical with older usable legacy",
				canonEntry:    newerExpiredCanonical,
				legacyEntry:   olderUsableLegacy,
				supersededKey: legacyKey,
			},
			{
				name:          "newer expired legacy with older usable canonical",
				canonEntry:    olderUsableCanonical,
				legacyEntry:   newerExpiredLegacy,
				supersededKey: canonicalKey,
			},
		} {
			require.NoError(t, host.SetSecret(ctx, canonicalKey, marshalEntry(ord.canonEntry)))
			require.NoError(t, host.SetSecret(ctx, legacyKey, marshalEntry(ord.legacyEntry)))
			require.NoError(t, setActiveCluster(ctx, host, prefix, cs.url()))

			fake.setDeleteErrorForKey(ord.supersededKey, errors.New("superseded logout delete blocked"))

			// 1. Per-cluster Logout preserves authoritative expired session on failure.
			require.Error(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: cs.url()}), ord.name)
			stClusterFail, serr := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, serr)
			assert.False(t, stClusterFail.Authenticated, "%s: partial per-cluster Logout must not revive older credential", ord.name)
			assert.Equal(t, "token expired", stClusterFail.Reason)
			_, terr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
			require.Error(t, terr)
			assert.Contains(t, terr.Error(), "token expired")

			// 2. Profile-wide Logout (empty Hostname) also preserves authoritative expired session on failure.
			require.Error(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}), ord.name)
			stAllFail, serr := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, serr)
			assert.False(t, stAllFail.Authenticated, "%s: partial profile Logout must not revive older credential", ord.name)
			assert.Equal(t, "token expired", stAllFail.Reason)
			_, terr = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
			require.Error(t, terr)
			assert.Contains(t, terr.Error(), "token expired")

			fake.setDeleteErrorForKey(ord.supersededKey, nil)
			require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
			stCleared, serr := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, serr)
			assert.False(t, stCleared.Authenticated)
			assert.Equal(t, "not logged in", stCleared.Reason)
		}

		// In-process per-profile RWMutex serialization and isolation:
		// 1. Holding the write lock on one profile blocks reads/writes on that
		//    same profile while allowing independent profiles to run unblocked.
		var latestLoginToken atomic.Value
		latestLoginToken.Store("concurrent-fresh-login")
		pConc := &Plugin{
			http: cs.srv.Client(),
			browser: func(ctx context.Context, rawURL string) error {
				tok, _ := latestLoginToken.Load().(string)
				return fakeBrowser(tok, 3600)(ctx, rawURL)
			},
		}
		require.NoError(t, pConc.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(fmt.Sprintf(`{"apiServerUrl":%q,"loginTimeout":"3s"}`, cs.url())),
			},
		}))

		alphaCtx := auth.WithProfile(hostContext(fake), "alpha")
		betaCtx := auth.WithProfile(hostContext(fake), "beta")
		alphaPrefix := profileKeyPrefix("alpha")
		alphaCanonKey := userTokenKey(alphaPrefix, cs.url())
		require.NoError(t, cacheSet(alphaCtx, host, alphaCanonKey, &newerLegacy))
		require.NoError(t, setActiveCluster(alphaCtx, host, alphaPrefix, cs.url()))

		alphaLogoutHeld := make(chan struct{})
		releaseAlphaLogout := make(chan struct{})
		var alphaHoldTriggered atomic.Bool
		fake.setBeforeDeleteHook(func(name string) {
			if name == alphaCanonKey && alphaHoldTriggered.CompareAndSwap(false, true) {
				close(alphaLogoutHeld)
				<-releaseAlphaLogout
			}
		})

		alphaLogoutDone := make(chan error, 1)
		go func() {
			alphaLogoutDone <- pConc.Logout(alphaCtx, HandlerName, sdkplugin.LogoutRequest{Hostname: cs.url()})
		}()
		<-alphaLogoutHeld

		// Same-profile GetStatus and GetToken block behind alpha's active write lock.
		alphaStatusDone := make(chan *auth.Status, 1)
		go func() {
			stAlpha, serr := pConc.GetStatus(alphaCtx, HandlerName, sdkplugin.StatusRequest{})
			assert.NoError(t, serr)
			alphaStatusDone <- stAlpha
		}()
		alphaTokenDone := make(chan error, 1)
		go func() {
			_, terr := pConc.GetToken(alphaCtx, HandlerName, sdkplugin.TokenRequest{})
			alphaTokenDone <- terr
		}()

		// Meanwhile, beta profile operations proceed immediately without blocking on alpha.
		latestLoginToken.Store("beta-unblocked-tok")
		_, betaLoginErr := pConc.Login(betaCtx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, betaLoginErr)
		betaTok, betaTokErr := pConc.GetToken(betaCtx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, betaTokErr)
		assert.Equal(t, "beta-unblocked-tok", betaTok.AccessToken)
		require.NoError(t, pConc.Logout(betaCtx, HandlerName, sdkplugin.LogoutRequest{}))

		select {
		case premature := <-alphaStatusDone:
			t.Fatalf("same-profile GetStatus must wait for active Logout write lock, got: %+v", premature)
		case prematureErr := <-alphaTokenDone:
			t.Fatalf("same-profile GetToken must wait for active Logout write lock, got: %v", prematureErr)
		default:
		}

		close(releaseAlphaLogout)
		require.NoError(t, <-alphaLogoutDone)
		fake.setBeforeDeleteHook(nil)

		afterAlphaSt := <-alphaStatusDone
		require.NotNil(t, afterAlphaSt)
		assert.False(t, afterAlphaSt.Authenticated, "queued GetStatus must observe completed Logout")
		require.Error(t, <-alphaTokenDone, "queued GetToken must reject logged-out session")

		// 2. Concurrent in-process Login, Logout, PurgeExpiredTokens, GetStatus,
		//    ListCachedTokens, and GetToken (legacy migration + SA minting) under -race.
		var raceWG sync.WaitGroup
		for i := 0; i < 8; i++ {
			idx := i
			raceWG.Add(4)
			go func() {
				defer raceWG.Done()
				latestLoginToken.Store(fmt.Sprintf("race-user-tok-%d", idx))
				_, _ = pConc.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
			}()
			go func() {
				defer raceWG.Done()
				if idx%2 == 0 {
					pConc.profileLock(ctx).Lock()
					_ = host.SetSecret(ctx, legacyKey, marshalEntry(newerLegacy))
					pConc.profileLock(ctx).Unlock()
				}
				_, _ = pConc.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
				_, _ = pConc.ListCachedTokens(ctx, HandlerName)
				_, _ = pConc.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
				_, _ = pConc.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "default/deployer"})
			}()
			go func() {
				defer raceWG.Done()
				_, _ = pConc.PurgeExpiredTokens(ctx, HandlerName)
			}()
			go func() {
				defer raceWG.Done()
				if idx%2 == 0 {
					_ = pConc.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: cs.url()})
				} else {
					_ = pConc.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{})
				}
			}()
		}
		raceWG.Wait()

		require.NoError(t, pConc.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
		remAfterLogout, lerr := pConc.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, lerr)
		assert.Empty(t, remAfterLogout)

		latestLoginToken.Store("final-clean-login-tok")
		_, err = pConc.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		finalTok, err := pConc.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "final-clean-login-tok", finalTok.AccessToken)
		require.NoError(t, pConc.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
	})

	t.Run("omitted expires_in anchors fixed expiry at capture time and rejects stale or over-demanding requests", func(t *testing.T) {
		cs := newClusterServer(t)
		// Browser callback omits expires_in (0).
		p := newWiredPlugin(t, cs, fakeBrowser("no-exp-tok", 0))
		fake := newFakeHostService()
		ctx := hostContext(fake)
		host := newFakeHostClient(fake)
		prefix := profileKeyPrefix("")

		loginResp, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		require.False(t, loginResp.ExpiresAt.IsZero())

		tok1, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		tok2, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{MinValidFor: 10 * time.Minute})
		require.NoError(t, err)
		assert.True(t, tok1.ExpiresAt.Equal(loginResp.ExpiresAt), "ExpiresAt must stay anchored to capture time")
		assert.True(t, tok2.ExpiresAt.Equal(loginResp.ExpiresAt), "MinValidFor must not extend reported ExpiresAt")

		// Demanding a lifetime longer than the anchored 24h TTL must fail closed.
		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{MinValidFor: 48 * time.Hour})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")

		// A pre-existing cached entry captured >24h ago with zero ExpiresAt must be treated as expired and purged.
		staleEntry := cacheEntry{
			AccessToken: "stale-25h-token",
			TokenType:   "Bearer",
			CachedAt:    time.Now().Add(-25 * time.Hour),
			Kind:        kindUser,
			APIServer:   cs.url(),
			Username:    "alice",
		}
		// #nosec G117 -- test fixture serialized for fake secret store
		staleRaw, err := json.Marshal(&staleEntry)
		require.NoError(t, err)
		require.NoError(t, host.SetSecret(ctx, userTokenKey(prefix, cs.url()), string(staleRaw)))

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")

		st, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{Hostname: cs.url()})
		require.NoError(t, err)
		assert.False(t, st.Authenticated)
		assert.Equal(t, "token expired", st.Reason)

		purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
		require.NoError(t, err)
		assert.Equal(t, 1, purged)
	})

	t.Run("active-cluster promotion and marker deletion errors propagate from Logout and PurgeExpiredTokens", func(t *testing.T) {
		clusterA := newClusterServer(t)
		clusterB := newClusterServer(t)
		p := &Plugin{http: http.DefaultClient, browser: fakeBrowser("t", 3600)}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))

		fake := newFakeHostService()
		ctx := hostContext(fake)
		host := newFakeHostClient(fake)
		prefix := profileKeyPrefix("")
		activeKey := activeClusterKey(prefix)

		// 1. Logout active cluster B when active-cluster promotion to A fails -> error returned.
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterA.url()), &cacheEntry{
			AccessToken: "tok-a",
			Kind:        kindUser,
			APIServer:   clusterA.url(),
			ExpiresAt:   time.Now().Add(time.Hour),
		}))
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterB.url()), &cacheEntry{
			AccessToken: "tok-b",
			Kind:        kindUser,
			APIServer:   clusterB.url(),
			ExpiresAt:   time.Now().Add(time.Hour),
		}))
		require.NoError(t, setActiveCluster(ctx, host, prefix, clusterB.url()))

		fake.setWriteErrorForKey(activeKey, errors.New("active marker write failed"))
		err := p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: clusterB.url()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "promote active cluster")
		fake.setWriteErrorForKey(activeKey, nil)

		// 2. Logout last cluster A when active-marker deletion fails -> error returned.
		require.NoError(t, setActiveCluster(ctx, host, prefix, clusterA.url()))
		fake.setDeleteErrorForKey(activeKey, errors.New("active marker delete failed"))
		err = p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: clusterA.url()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete active cluster marker")
		fake.setDeleteErrorForKey(activeKey, nil)

		// 3. PurgeExpiredTokens preserves purged count when active-cluster promotion or marker deletion fails.
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterA.url()), &cacheEntry{
			AccessToken: "live-a",
			Kind:        kindUser,
			APIServer:   clusterA.url(),
			ExpiresAt:   time.Now().Add(time.Hour),
		}))
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterB.url()), &cacheEntry{
			AccessToken: "expired-b",
			Kind:        kindUser,
			APIServer:   clusterB.url(),
			ExpiresAt:   time.Now().Add(-time.Hour),
		}))
		require.NoError(t, setActiveCluster(ctx, host, prefix, clusterB.url()))

		fake.setWriteErrorForKey(activeKey, errors.New("promote write failed"))
		purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
		require.Error(t, err)
		assert.Equal(t, 1, purged, "purged count must be preserved even when active marker update fails")
		assert.Contains(t, err.Error(), "promote active cluster")
		fake.setWriteErrorForKey(activeKey, nil)

		// Remove live cluster A, re-seed expired B, and fail marker deletion on purge.
		require.NoError(t, host.DeleteSecret(ctx, userTokenKey(prefix, clusterA.url())))
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterB.url()), &cacheEntry{
			AccessToken: "expired-b-2",
			Kind:        kindUser,
			APIServer:   clusterB.url(),
			ExpiresAt:   time.Now().Add(-time.Hour),
		}))
		require.NoError(t, setActiveCluster(ctx, host, prefix, clusterB.url()))
		fake.setDeleteErrorForKey(activeKey, errors.New("marker delete failed"))
		purged, err = p.PurgeExpiredTokens(ctx, HandlerName)
		require.Error(t, err)
		assert.Equal(t, 1, purged)
		assert.Contains(t, err.Error(), "delete active cluster marker")
		fake.setDeleteErrorForKey(activeKey, nil)
	})

	t.Run("CLI clientId override takes precedence over configured oauthClientId and cluster alias oauthClientId", func(t *testing.T) {
		cs := newClusterServer(t)
		var gotClientID string
		p := &Plugin{
			http: cs.srv.Client(),
			browser: func(ctx context.Context, rawURL string) error {
				u, err := url.Parse(rawURL)
				if err != nil {
					return err
				}
				gotClientID = u.Query().Get("client_id")
				return fakeBrowser("cid-tok", 3600)(ctx, rawURL)
			},
		}
		// Simulate scafctl ApplyOverrides merging "clientId" alongside existing "oauthClientId".
		mergedSettings := map[string]json.RawMessage{
			HandlerName: json.RawMessage(fmt.Sprintf(
				`{"apiServerUrl":%q,"oauthClientId":"configured-client","clientId":"cli-override-client","loginTimeout":"3s","clusters":{"prod":{"url":%q,"oauthClientId":"cluster-alias-client"}}}`,
				cs.url(), cs.url(),
			)),
		}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Settings: mergedSettings,
		}))
		assert.Equal(t, "cli-override-client", p.config.OAuthClientID)

		fake := newFakeHostService()
		ctx := hostContext(fake)

		// Direct login uses CLI override over handler oauthClientId.
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "cli-override-client", gotClientID)

		// Named cluster login also honors CLI override over cluster alias oauthClientId.
		gotClientID = ""
		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Hostname: "prod"}, nil)
		require.NoError(t, err)
		assert.Equal(t, "cli-override-client", gotClientID)

		// Flat per-RPC settings containing both keys also honor clientId precedence.
		flatBoth := map[string]json.RawMessage{
			"apiServerUrl":  json.RawMessage(fmt.Sprintf("%q", cs.url())),
			"oauthClientId": json.RawMessage(`"flat-configured"`),
			"clientId":      json.RawMessage(`"flat-cli-override"`),
			"loginTimeout":  json.RawMessage(`"3s"`),
		}
		gotClientID = ""
		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Settings: flatBoth}, nil)
		require.NoError(t, err)
		assert.Equal(t, "flat-cli-override", gotClientID)

		// Outer "clientId" merged alongside nested "settings" preserves inner apiServerUrl/clusters while overriding clientId.
		nestedWithOverride := map[string]json.RawMessage{
			HandlerName: json.RawMessage(fmt.Sprintf(
				`{"clientId":"nested-cli-override","settings":{"apiServerUrl":%q,"oauthClientId":"inner-configured","loginTimeout":"3s"}}`,
				cs.url(),
			)),
		}
		nestedCtx := sdkplugin.WithRequestSettings(ctx, nestedWithOverride)
		gotClientID = ""
		_, err = p.Login(nestedCtx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "nested-cli-override", gotClientID)
	})
}
