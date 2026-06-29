// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClusterAliasPlugin configures a plugin with a clusters alias map and no
// top-level apiServerUrl, pointed at the fake cluster server.
func newClusterAliasPlugin(t *testing.T, cs *clusterServer, alias, oauthClientID string, browser browserOpener) *Plugin {
	t.Helper()
	p := &Plugin{http: cs.srv.Client(), browser: browser}
	clusters := map[string]Cluster{alias: {URL: cs.url(), OAuthClientID: oauthClientID}}
	raw, err := json.Marshal(clusters)
	require.NoError(t, err)
	cfg := sdkplugin.ProviderConfig{Settings: map[string]json.RawMessage{"clusters": raw}}
	require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, cfg))
	p.config.LoginTimeout = 3 * time.Second
	return p
}

func TestLoginHostname(t *testing.T) {
	cs := newClusterServer(t)

	t.Run("alias selects cluster url and client override", func(t *testing.T) {
		p := newClusterAliasPlugin(t, cs, "lab", "alias-client", fakeBrowser("alias-token", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)

		resp, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Hostname: "lab"}, nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Claims)
		assert.Equal(t, DefaultOAuthClientID, p.config.OAuthClientID, "alias client override applies to the per-login copy, not stored config")

		entry, err := cacheGet(ctx, newFakeHostClient(fake), userTokenKey(profileKeyPrefix(""), cs.url()))
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, "alias-token", entry.AccessToken)
	})

	t.Run("direct url hostname", func(t *testing.T) {
		p := &Plugin{http: cs.srv.Client(), browser: fakeBrowser("direct-token", 3600)}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))
		p.config.LoginTimeout = 3 * time.Second
		fake := newFakeHostService()
		ctx := hostContext(fake)

		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Hostname: cs.url()}, nil)
		require.NoError(t, err)

		entry, err := cacheGet(ctx, newFakeHostClient(fake), userTokenKey(profileKeyPrefix(""), cs.url()))
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, "direct-token", entry.AccessToken)
	})

	t.Run("unknown alias rejected", func(t *testing.T) {
		p := newClusterAliasPlugin(t, cs, "lab", "", fakeBrowser("t", 3600))
		_, err := p.Login(hostContext(newFakeHostService()), HandlerName, sdkplugin.LoginRequest{Hostname: "missing"}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown cluster")
	})
}

// TestLogoutHostnameClearsOnlyThatCluster verifies that a per-cluster logout
// (LogoutRequest.Hostname, advertised via auth.CapHostname) clears just that
// cluster's credential and leaves other clusters intact.
func TestLogoutHostnameClearsOnlyThatCluster(t *testing.T) {
	cs := newClusterServer(t)
	p := &Plugin{http: cs.srv.Client(), browser: fakeBrowser("t", 3600)}
	require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{}))

	fake := newFakeHostService()
	ctx := hostContext(fake)
	host := newFakeHostClient(fake)
	prefix := profileKeyPrefix("")

	clusterA := "https://api.a.example:6443"
	clusterB := "https://api.b.example:6443"
	require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterA), &cacheEntry{AccessToken: "a", APIServer: clusterA, Kind: kindUser}))
	require.NoError(t, cacheSet(ctx, host, userTokenKey(prefix, clusterB), &cacheEntry{AccessToken: "b", APIServer: clusterB, Kind: kindUser}))

	require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{Hostname: clusterA}))

	a, err := cacheGet(ctx, host, userTokenKey(prefix, clusterA))
	require.NoError(t, err)
	assert.Nil(t, a, "cluster A credential should be cleared")
	b, err := cacheGet(ctx, host, userTokenKey(prefix, clusterB))
	require.NoError(t, err)
	require.NotNil(t, b, "cluster B credential must remain")
	assert.Equal(t, "b", b.AccessToken)
}

func TestActiveClusterFallback(t *testing.T) {
	cs := newClusterServer(t)

	t.Run("get status falls back to active cluster", func(t *testing.T) {
		p := newClusterAliasPlugin(t, cs, "lab", "", fakeBrowser("active-token", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Hostname: "lab"}, nil)
		require.NoError(t, err)

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, "jane.doe", status.Claims.Username)
	})

	t.Run("get token falls back to active cluster", func(t *testing.T) {
		p := newClusterAliasPlugin(t, cs, "lab", "", fakeBrowser("active-token", 3600))
		fake := newFakeHostService()
		ctx := hostContext(fake)
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Hostname: "lab"}, nil)
		require.NoError(t, err)

		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "active-token", tok.AccessToken)
	})

	t.Run("status unauthenticated without active cluster", func(t *testing.T) {
		p := newClusterAliasPlugin(t, cs, "lab", "", fakeBrowser("t", 3600))
		status, err := p.GetStatus(hostContext(newFakeHostService()), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
		assert.Equal(t, "not logged in", status.Reason)
	})
}

func TestSetGetActiveCluster(t *testing.T) {
	fake := newFakeHostService()
	ctx := hostContext(fake)
	host := newFakeHostClient(fake)
	prefix := profileKeyPrefix("")

	assert.Empty(t, getActiveCluster(ctx, host, prefix))
	require.NoError(t, setActiveCluster(ctx, host, prefix, "https://api.example.test:6443"))
	assert.Equal(t, "https://api.example.test:6443", getActiveCluster(ctx, host, prefix))

	// Nil host is handled gracefully.
	assert.Empty(t, getActiveCluster(ctx, nil, prefix))
	require.Error(t, setActiveCluster(ctx, nil, prefix, "https://x"))
}
