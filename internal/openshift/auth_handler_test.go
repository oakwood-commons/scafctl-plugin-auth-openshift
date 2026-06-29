// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoginHonorsCallbackPort verifies that a host-requested callback port
// (forwarded via LoginRequest.CallbackPort for handlers advertising
// auth.CapCallbackPort) is used to bind the loopback OAuth callback server, so
// the redirect URI sent to the browser targets that exact port.
func TestLoginHonorsCallbackPort(t *testing.T) {
	cs := newClusterServer(t)

	// Reserve a free port, then release it so Login can bind it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	var gotRedirect string
	inner := fakeBrowser("tok", 3600)
	capturing := func(ctx context.Context, rawURL string) error {
		u, perr := url.Parse(rawURL)
		if perr != nil {
			return perr
		}
		gotRedirect = u.Query().Get("redirect_uri")
		return inner(ctx, rawURL)
	}

	p := newWiredPlugin(t, cs, capturing)
	ctx := hostContext(newFakeHostService())
	_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{CallbackPort: port}, nil)
	require.NoError(t, err)
	assert.Contains(t, gotRedirect, fmt.Sprintf("127.0.0.1:%d", port),
		"login must bind the host-requested callback port")
}

// TestLoginIgnoresOutOfRangeCallbackPort ensures an out-of-range port falls
// back to an ephemeral port rather than failing to listen.
func TestLoginIgnoresOutOfRangeCallbackPort(t *testing.T) {
	cs := newClusterServer(t)
	p := newWiredPlugin(t, cs, fakeBrowser("tok", 3600))
	ctx := hostContext(newFakeHostService())
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{CallbackPort: 80}, nil)
	require.NoError(t, err, "out-of-range callback port should fall back to ephemeral, not error")
}

func TestGetAuthHandlers(t *testing.T) {
	p := &Plugin{}
	require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))

	handlers, err := p.GetAuthHandlers(context.Background())
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	assert.Equal(t, HandlerName, handlers[0].Name)
	assert.Equal(t, "OpenShift", handlers[0].DisplayName)
	require.NotEmpty(t, handlers[0].Flows)
	assert.Equal(t, "interactive", string(handlers[0].Flows[0]))
	// Advertises both hostname capabilities: CapHostname (login) and
	// CapTokenHostname (per-request token selection for multi-cluster).
	assert.Contains(t, handlers[0].Capabilities, auth.CapHostname)
	assert.Contains(t, handlers[0].Capabilities, auth.CapTokenHostname)
	// Advertises CapInstanceHostname so the host can render a per-cluster
	// status row (via Status.Hostname / CachedTokenInfo.Hostname).
	assert.Contains(t, handlers[0].Capabilities, auth.CapInstanceHostname)
	// Advertises per-request scopes so `auth token --scope <ns>/<sa>` reaches
	// GetToken to mint a scoped service-account token.
	assert.Contains(t, handlers[0].Capabilities, auth.CapScopesOnTokenRequest)
}

func TestConfigureAuthHandler(t *testing.T) {
	t.Run("known handler applies settings", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, mustSettings(t, "https://api.example.test:6443"))
		require.NoError(t, err)
		assert.Equal(t, "https://api.example.test:6443", p.config.APIServerURL)
		assert.Equal(t, DefaultOAuthClientID, p.config.OAuthClientID)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), "unknown", sdkplugin.ProviderConfig{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})
}

func TestLogin(t *testing.T) {
	cs := newClusterServer(t)

	t.Run("successful web login holds credential", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("user-oauth-token", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)

		resp, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Claims)
		assert.Equal(t, "jane.doe", resp.Claims.Username)
		assert.False(t, resp.ExpiresAt.IsZero())

		// Token is persisted in the host secret store.
		entry, err := cacheGet(ctx, newFakeHostClient(fake), userTokenKey(profileKeyPrefix(""), cs.url()))
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, "user-oauth-token", entry.AccessToken)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
		_, err := p.Login(context.Background(), "unknown", sdkplugin.LoginRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("unsupported flow rejected", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
		_, err := p.Login(hostContext(newFakeHostService()), HandlerName, sdkplugin.LoginRequest{Flow: "device_code"}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported flow")
	})

	t.Run("missing api server", func(t *testing.T) {
		p := &Plugin{http: cs.srv.Client(), browser: fakeBrowser("t", 3600)}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))
		_, err := p.Login(hostContext(newFakeHostService()), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api server URL is required")
	})

	t.Run("oauth denied", func(t *testing.T) {
		p := newWiredPlugin(t, cs, errorBrowser())
		_, err := p.Login(hostContext(newFakeHostService()), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
	})
}

func TestGetStatus(t *testing.T) {
	cs := newClusterServer(t)

	t.Run("not logged in", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
		status, err := p.GetStatus(hostContext(newFakeHostService()), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
		assert.Equal(t, "not logged in", status.Reason)
	})

	t.Run("authenticated after login", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("tok", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, "jane.doe", status.Claims.Username)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
		_, err := p.GetStatus(context.Background(), "unknown", sdkplugin.StatusRequest{})
		require.Error(t, err)
	})
}

func TestGetTokenUser(t *testing.T) {
	cs := newClusterServer(t)

	t.Run("not authenticated", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
		_, err := p.GetToken(hostContext(newFakeHostService()), HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authenticated")
	})

	t.Run("returns held token", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("held-token", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)

		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "held-token", tok.AccessToken)
		assert.Equal(t, "Bearer", tok.TokenType)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
		_, err := p.GetToken(context.Background(), "unknown", sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})
}

func TestGetTokenServiceAccount(t *testing.T) {
	cs := newClusterServer(t)
	p := newWiredPlugin(t, cs, fakeBrowser("held-token", 3600))
	fake := newFakeHostService()
	ctx := hostContext(fake)
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
	require.NoError(t, err)

	t.Run("mints SA token", func(t *testing.T) {
		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "infra-auto/pipeline@openshift"})
		require.NoError(t, err)
		assert.Equal(t, "sa-minted-token", tok.AccessToken)
	})

	t.Run("uses cache on second call", func(t *testing.T) {
		cs.saToken = "different-token" // would differ if re-minted
		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: "infra-auto/pipeline@openshift"})
		require.NoError(t, err)
		assert.Equal(t, "sa-minted-token", tok.AccessToken, "should return cached token")
		cs.saToken = "sa-minted-token"
	})

	t.Run("requires login", func(t *testing.T) {
		p2 := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
		_, err := p2.GetToken(hostContext(newFakeHostService()), HandlerName, sdkplugin.TokenRequest{Scope: "ns/sa"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authenticated")
	})
}

// TestGetTokenHostnameSelectsCluster verifies that a per-request hostname
// (forwarded by the host under CapTokenHostname) selects the correct per-cluster
// token, so multi-cluster kubeconfig contexts do not collide on the most-recent
// login. An empty hostname preserves the configured/active-cluster behavior.
func TestGetTokenHostnameSelectsCluster(t *testing.T) {
	cs := newClusterServer(t)
	p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
	fake := newFakeHostService()
	ctx := hostContext(fake)
	host := newFakeHostClient(fake)
	prefix := profileKeyPrefix("")

	// Two clusters' user tokens coexist in the store, keyed by API server.
	// serverA is the configured cluster (newWiredPlugin sets apiServerUrl=cs.url()).
	serverA := cs.url()
	serverB := "https://api.clusterb.example.test:6443"
	seed := func(server, token string) {
		t.Helper()
		require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, server), &cacheEntry{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
			CachedAt:    time.Now(),
			Kind:        kindUser,
			APIServer:   server,
		}))
	}
	seed(serverA, "token-a")
	seed(serverB, "token-b")
	// The most-recently-active cluster is B; without a hostname the old behavior
	// would return B's token for every context.
	require.NoError(t, setActiveCluster(ctx, host, prefix, serverB))

	t.Run("hostname selects cluster A", func(t *testing.T) {
		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: serverA})
		require.NoError(t, err)
		assert.Equal(t, "token-a", tok.AccessToken)
	})

	t.Run("hostname selects cluster B", func(t *testing.T) {
		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: serverB})
		require.NoError(t, err)
		assert.Equal(t, "token-b", tok.AccessToken)
	})

	t.Run("empty hostname uses configured cluster", func(t *testing.T) {
		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "token-a", tok.AccessToken, "configured apiServerUrl selects cluster A")
	})

	t.Run("unresolvable hostname errors", func(t *testing.T) {
		_, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Hostname: "not-a-known-alias"})
		require.Error(t, err)
	})
}

func TestLogout(t *testing.T) {
	cs := newClusterServer(t)
	p := newWiredPlugin(t, cs, fakeBrowser("tok", 3600))
	fake := newFakeHostService()
	ctx := hostContext(fake)

	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
	require.NoError(t, err)

	require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))

	status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.False(t, status.Authenticated)

	t.Run("unknown handler", func(t *testing.T) {
		require.Error(t, p.Logout(context.Background(), "unknown", sdkplugin.LogoutRequest{}))
	})
}

func TestListAndPurgeTokens(t *testing.T) {
	cs := newClusterServer(t)
	p := newWiredPlugin(t, cs, fakeBrowser("tok", 3600))
	fake := newFakeHostService()
	ctx := hostContext(fake)
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
	require.NoError(t, err)

	tokens, err := p.ListCachedTokens(ctx, HandlerName)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, kindUser, tokens[0].TokenKind)

	// Nothing expired yet.
	count, err := p.PurgeExpiredTokens(ctx, HandlerName)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	t.Run("unknown handler", func(t *testing.T) {
		_, err := p.ListCachedTokens(context.Background(), "unknown")
		require.Error(t, err)
		_, err = p.PurgeExpiredTokens(context.Background(), "unknown")
		require.Error(t, err)
	})
}

func TestPurgeExpired(t *testing.T) {
	fake := newFakeHostService()
	ctx := hostContext(fake)
	host := newFakeHostClient(fake)

	// Seed one expired and one valid entry.
	require.NoError(t, cacheSet(ctx, host, userTokenKey(profileKeyPrefix(""), "https://a"), &cacheEntry{
		AccessToken: "x", Kind: kindUser, ExpiresAt: time.Now().Add(-time.Hour),
	}))
	require.NoError(t, cacheSet(ctx, host, userTokenKey(profileKeyPrefix(""), "https://b"), &cacheEntry{
		AccessToken: "y", Kind: kindUser, ExpiresAt: time.Now().Add(time.Hour),
	}))

	count, err := cachePurgeExpired(ctx, host, profileKeyPrefix(""))
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestDetectAvailableFlows(t *testing.T) {
	p := &Plugin{}
	require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))

	flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.True(t, flows[0].Available)

	_, err = p.DetectAvailableFlows(context.Background(), "unknown")
	require.Error(t, err)
}

func TestStopAuthHandler(t *testing.T) {
	p := &Plugin{}
	require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))
}

func TestProfileIsolation(t *testing.T) {
	cs := newClusterServer(t)
	p := newWiredPlugin(t, cs, fakeBrowser("work-token", 3600))
	fake := newFakeHostService()

	workCtx := auth.WithProfile(hostContext(fake), "work")
	_, err := p.Login(workCtx, HandlerName, sdkplugin.LoginRequest{}, nil)
	require.NoError(t, err)

	// Same host store, different profile: credential must not leak.
	personalCtx := auth.WithProfile(hostContext(fake), "personal")
	status, err := p.GetStatus(personalCtx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.False(t, status.Authenticated, "credential must not leak across profiles")

	// The work profile still sees its own credential.
	status, err = p.GetStatus(workCtx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, status.Authenticated)

	// ListCachedTokens is scoped per profile.
	personalTokens, err := p.ListCachedTokens(personalCtx, HandlerName)
	require.NoError(t, err)
	assert.Empty(t, personalTokens)
	workTokens, err := p.ListCachedTokens(workCtx, HandlerName)
	require.NoError(t, err)
	require.Len(t, workTokens, 1)

	// Logout on the personal profile leaves the work credential intact.
	require.NoError(t, p.Logout(personalCtx, HandlerName, sdkplugin.LogoutRequest{}))
	status, err = p.GetStatus(workCtx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, status.Authenticated, "logout on another profile must not clear ours")
}

func TestGetTokenMinValidFor(t *testing.T) {
	cs := newClusterServer(t)
	// Token that expires in ~90s: satisfies the default 60s leeway only.
	p := newWiredPlugin(t, cs, fakeBrowser("short-token", 90))
	fake := newFakeHostService()
	ctx := hostContext(fake)
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
	require.NoError(t, err)

	tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, "short-token", tok.AccessToken)

	// Demanding 10m of remaining validity fails: the token expires sooner.
	_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{MinValidFor: 10 * time.Minute})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")
}

func TestLoginRejectsNonLoopbackCallbackHost(t *testing.T) {
	cs := newClusterServer(t)
	p := newWiredPlugin(t, cs, fakeBrowser("t", 3600))
	p.config.CallbackHost = "0.0.0.0"
	_, err := p.Login(hostContext(newFakeHostService()), HandlerName, sdkplugin.LoginRequest{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loopback")
}
