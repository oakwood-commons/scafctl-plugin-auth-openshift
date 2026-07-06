// Package openshift implements the openshift auth handler plugin.
//
// The handler performs the OpenShift OAuth browser web-login (implicit grant)
// and holds the resulting credential in the host secret store. It can also mint
// scoped service-account tokens via the Kubernetes TokenRequest API. All
// cluster- and org-specific values are configuration-driven so the handler
// stays generic.
package openshift

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// HandlerName is the unique identifier for this auth handler.
	HandlerName = "openshift"

	// Version is the auth handler version.
	Version = "0.1.0"
)

// apiServerEnvVars are checked, in order, as a fallback source for the cluster
// API server URL when it is not set in handler configuration.
var apiServerEnvVars = []string{"OPENSHIFT_API_SERVER", "KUBERNETES_API_SERVER"}

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	cfg     sdkplugin.ProviderConfig
	config  *Config
	http    httpDoer
	browser browserOpener
}

// GetAuthHandlers returns the list of auth handlers exposed by this plugin.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetAuthHandlers(_ context.Context) ([]sdkplugin.AuthHandlerInfo, error) {
	return []sdkplugin.AuthHandlerInfo{
		{
			Name:        HandlerName,
			DisplayName: "OpenShift",
			Flows:       []auth.Flow{auth.FlowInteractive},
			Capabilities: []auth.Capability{
				auth.CapCallbackPort,
				auth.CapHostname,
				auth.CapTokenHostname,
				auth.CapInstanceHostname,
				auth.CapScopesOnTokenRequest,
			},
		},
	}, nil
}

// ConfigureAuthHandler stores host-side configuration and initializes plugin
// state. It runs once at plugin load, before Login/GetToken.
func (p *Plugin) ConfigureAuthHandler(ctx context.Context, handlerName string, cfg sdkplugin.ProviderConfig) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	p.cfg = cfg

	config := DefaultConfig()
	if err := config.applySettings(cfg.Settings); err != nil {
		return fmt.Errorf("apply handler settings: %w", err)
	}
	config.normalize()
	p.config = config

	if p.http == nil {
		p.http = newHTTPClient(DefaultHTTPTimeout, config.InsecureSkipTLSVerify)
	}
	if p.browser == nil {
		p.browser = defaultBrowserOpener
	}
	logr.FromContextOrDiscard(ctx).V(1).Info("configured openshift auth handler", "version", Version)
	return nil
}

// Login performs the OpenShift OAuth browser web-login and holds the resulting
// token in the host secret store.
//
//nolint:revive // deviceCodeCb param required by interface
func (p *Plugin) Login(ctx context.Context, handlerName string, req sdkplugin.LoginRequest, _ func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	if req.Flow != "" && req.Flow != auth.FlowInteractive {
		return nil, fmt.Errorf("unsupported flow %q: openshift supports %q", req.Flow, auth.FlowInteractive)
	}

	lgr := logr.FromContextOrDiscard(ctx)
	cfg := p.effectiveConfig(req.Timeout)

	// Honor a host-requested loopback callback port (advertised via
	// auth.CapCallbackPort). Zero keeps the ephemeral-port default. The host
	// validates the range before forwarding, but guard anyway so an out-of-range
	// value falls back to an ephemeral port rather than failing to listen.
	if req.CallbackPort >= 1024 && req.CallbackPort <= 65535 {
		cfg.CallbackPort = req.CallbackPort
		lgr.V(1).Info("using host-requested OAuth callback port", "port", req.CallbackPort)
	}

	apiServer := cfg.APIServerURL
	if req.Hostname != "" {
		resolvedURL, clientID, err := cfg.resolveCluster(req.Hostname)
		if err != nil {
			return nil, fmt.Errorf("openshift: %w", err)
		}
		apiServer = resolvedURL
		if clientID != "" {
			cfg.OAuthClientID = clientID
		}
	}
	if apiServer == "" {
		return nil, fmt.Errorf("api server URL is required; set it in handler config, pass --hostname, or %s", strings.Join(apiServerEnvVars, "/"))
	}
	cfg.APIServerURL = apiServer

	meta, err := discoverOAuthMetadata(ctx, p.http, apiServer)
	if err != nil {
		return nil, fmt.Errorf("openshift: %w", err)
	}

	result, err := runWebLogin(ctx, cfg, meta, p.browser)
	if err != nil {
		return nil, fmt.Errorf("openshift: web login: %w", err)
	}

	username := resolveUsername(ctx, p.http, apiServer, result.AccessToken)

	entry := &cacheEntry{
		AccessToken: result.AccessToken,
		TokenType:   result.TokenType,
		ExpiresAt:   result.ExpiresAt,
		CachedAt:    time.Now(),
		Flow:        auth.FlowInteractive,
		Kind:        kindUser,
		APIServer:   apiServer,
		Username:    username,
	}
	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))
	if host := sdkplugin.HostClientFromContext(ctx); host != nil {
		if err := cacheSet(ctx, host, userTokenKey(prefix, apiServer), entry); err != nil {
			lgr.V(1).Info("failed to cache token (continuing)", "error", err.Error())
		}
		if err := setActiveCluster(ctx, host, prefix, apiServer); err != nil {
			lgr.V(1).Info("failed to record active cluster (continuing)", "error", err.Error())
		}
	}

	lgr.V(1).Info("openshift login completed", "user", username, "apiServer", apiServer)
	return &sdkplugin.LoginResponse{
		Claims:    claimsFromEntry(entry, meta.Issuer),
		ExpiresAt: entry.ExpiresAt,
	}, nil
}

// Logout clears cached openshift credentials. An empty req.Hostname clears
// every cluster for the profile; a hostname (advertised via auth.CapHostname)
// clears just that cluster's user and service-account tokens.
func (p *Plugin) Logout(ctx context.Context, handlerName string, req sdkplugin.LogoutRequest) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	lgr := logr.FromContextOrDiscard(ctx)
	host := sdkplugin.HostClientFromContext(ctx)
	if host == nil {
		return nil
	}
	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))
	if req.Hostname != "" {
		apiServer, _, err := p.effectiveConfig(0).resolveCluster(req.Hostname)
		if err != nil {
			return fmt.Errorf("openshift: %w", err)
		}
		cacheClearCluster(ctx, lgr, host, prefix, apiServer)
		return nil
	}
	cacheClearAll(ctx, lgr, host, prefix)
	return nil
}

// GetStatus reports current authentication status without side effects. A
// req.Hostname (advertised via auth.CapHostname) selects the cluster to report;
// otherwise it falls back to the configured then active cluster.
func (p *Plugin) GetStatus(ctx context.Context, handlerName string, req sdkplugin.StatusRequest) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	host := sdkplugin.HostClientFromContext(ctx)
	if host == nil {
		return &auth.Status{Authenticated: false, Reason: "secret store unavailable"}, nil
	}

	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))
	apiServer := p.effectiveConfig(0).APIServerURL
	if req.Hostname != "" {
		resolved, _, err := p.effectiveConfig(0).resolveCluster(req.Hostname)
		if err != nil {
			return &auth.Status{Authenticated: false, Reason: err.Error()}, nil
		}
		apiServer = resolved
	}
	if apiServer == "" {
		apiServer = getActiveCluster(ctx, host, prefix)
	}
	if apiServer == "" {
		return &auth.Status{Authenticated: false, Reason: "not logged in"}, nil
	}

	entry, err := cacheGet(ctx, host, userTokenKey(prefix, apiServer))
	if err != nil {
		return &auth.Status{Authenticated: false, Reason: err.Error()}, nil
	}
	if entry == nil {
		return &auth.Status{Authenticated: false, Reason: "not logged in"}, nil
	}
	if !entry.isUsable() {
		return &auth.Status{Authenticated: false, Reason: "token expired"}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims:        claimsFromEntry(entry, ""),
		ExpiresAt:     entry.ExpiresAt,
		IdentityType:  auth.IdentityTypeUser,
		Flow:          auth.FlowInteractive,
		Hostname:      apiServer,
	}, nil
}

// GetToken returns a usable token. With an empty scope it returns the held user
// OAuth token. When the scope encodes a service account (see parseSAScope) it
// mints (and caches) a scoped service-account token via the TokenRequest API.
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	host := sdkplugin.HostClientFromContext(ctx)
	if host == nil {
		return nil, fmt.Errorf("secret store unavailable")
	}

	cfg := p.effectiveConfig(0)
	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))

	// Select the target cluster. An explicit per-request hostname wins: the host
	// forwards it (gated on auth.CapTokenHostname) from the kubectl/oc exec
	// credential's cluster, so each multi-cluster kubeconfig context receives its
	// own token instead of the most-recently-active one. When it is empty we fall
	// back to the configured cluster and finally the active cluster, preserving
	// single-cluster and older-host behavior.
	apiServer := cfg.APIServerURL
	if req.Hostname != "" {
		resolved, _, err := cfg.resolveCluster(req.Hostname)
		if err != nil {
			return nil, fmt.Errorf("openshift: %w", err)
		}
		apiServer = resolved
	}
	if apiServer == "" {
		apiServer = getActiveCluster(ctx, host, prefix)
	}
	if apiServer == "" {
		return nil, fmt.Errorf("api server URL is required; set it in handler config, pass --hostname, or %s", strings.Join(apiServerEnvVars, "/"))
	}

	if sa, ok := parseSAScope(req.Scope); ok {
		return p.getServiceAccountToken(ctx, host, prefix, apiServer, sa, req)
	}
	return p.getUserToken(ctx, host, prefix, apiServer, req.MinValidFor)
}

// getUserToken returns the held user OAuth token if still usable.
func (p *Plugin) getUserToken(ctx context.Context, host *sdkplugin.HostServiceClient, prefix, apiServer string, minValidFor time.Duration) (*sdkplugin.TokenResponse, error) {
	entry, err := cacheGet(ctx, host, userTokenKey(prefix, apiServer))
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.AccessToken == "" {
		return nil, fmt.Errorf("not authenticated")
	}
	if !entry.isUsableFor(minValidFor) {
		return nil, fmt.Errorf("token expired: run login again")
	}
	return tokenResponseFromEntry(entry), nil
}

// getServiceAccountToken returns a cached SA token or mints a fresh one.
func (p *Plugin) getServiceAccountToken(ctx context.Context, host *sdkplugin.HostServiceClient, prefix, apiServer string, sa saScope, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	key := saTokenKey(prefix, apiServer, sa.Namespace, sa.ServiceAccount, sa.Audience)
	if !req.ForceRefresh {
		if cached, err := cacheGet(ctx, host, key); err == nil && cached != nil && cached.isUsableFor(req.MinValidFor) {
			return tokenResponseFromEntry(cached), nil
		}
	}

	user, err := cacheGet(ctx, host, userTokenKey(prefix, apiServer))
	if err != nil {
		return nil, err
	}
	if user == nil || !user.isUsable() {
		return nil, fmt.Errorf("not authenticated: log in before minting a service-account token")
	}

	minted, err := mintServiceAccountToken(ctx, p.http, mintSAParams{
		APIServerURL:   apiServer,
		BearerToken:    user.AccessToken,
		Namespace:      sa.Namespace,
		ServiceAccount: sa.ServiceAccount,
		Audience:       sa.Audience,
	})
	if err != nil {
		return nil, err
	}
	minted.Flow = auth.FlowInteractive
	if err := cacheSet(ctx, host, key, minted); err != nil {
		logr.FromContextOrDiscard(ctx).V(1).Info("failed to cache minted token (continuing)", "error", err.Error())
	}
	return tokenResponseFromEntry(minted), nil
}

// ListCachedTokens returns information about cached tokens.
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	return cacheList(ctx, sdkplugin.HostClientFromContext(ctx), profileKeyPrefix(auth.ProfileFromContext(ctx)))
}

// PurgeExpiredTokens removes expired tokens from the cache.
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}
	return cachePurgeExpired(ctx, sdkplugin.HostClientFromContext(ctx), profileKeyPrefix(auth.ProfileFromContext(ctx)))
}

// StopAuthHandler performs cleanup for the named handler.
//
//nolint:revive // all params required by interface
func (p *Plugin) StopAuthHandler(_ context.Context, _ string) error {
	return nil
}

// DetectAvailableFlows reports which auth flows are usable in the current
// environment.
//
//nolint:revive // ctx required by interface
func (p *Plugin) DetectAvailableFlows(_ context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	return []sdkplugin.FlowAvailability{
		{Flow: auth.FlowInteractive, Available: true, Reason: "browser-based OAuth login"},
	}, nil
}

// effectiveConfig returns a config copy with env fallbacks and the per-login
// timeout applied.
func (p *Plugin) effectiveConfig(timeout time.Duration) *Config {
	cfg := DefaultConfig()
	if p.config != nil {
		c := *p.config
		// Deep-copy the Clusters map: the struct copy above shares the same
		// backing map, and normalize() writes trimmed URLs back into it. Under
		// concurrent RPCs (login/status/token) that would be a concurrent map
		// write on the shared p.config. Give each effective config its own map.
		if c.Clusters != nil {
			clusters := make(map[string]Cluster, len(c.Clusters))
			for k, v := range c.Clusters {
				clusters[k] = v
			}
			c.Clusters = clusters
		}
		cfg = &c
	}
	if cfg.APIServerURL == "" {
		cfg.APIServerURL = apiServerFromEnv()
	}
	if timeout > 0 {
		cfg.LoginTimeout = timeout
	}
	cfg.normalize()
	return cfg
}

// apiServerFromEnv resolves the API server URL from environment variables.
func apiServerFromEnv() string {
	for _, key := range apiServerEnvVars {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return strings.TrimRight(v, "/")
		}
	}
	return ""
}

// claimsFromEntry builds normalized claims from a cached entry.
func claimsFromEntry(e *cacheEntry, issuer string) *auth.Claims {
	name := e.Username
	if name == "" {
		name = e.ServiceAccount
	}
	return &auth.Claims{
		Issuer:    issuer,
		Subject:   name,
		Username:  name,
		Name:      name,
		ExpiresAt: e.ExpiresAt,
		IssuedAt:  e.CachedAt,
	}
}

// tokenResponseFromEntry adapts a cached entry to a plugin TokenResponse.
func tokenResponseFromEntry(e *cacheEntry) *sdkplugin.TokenResponse {
	return &sdkplugin.TokenResponse{
		AccessToken: e.AccessToken,
		TokenType:   firstNonEmpty(e.TokenType, "Bearer"),
		ExpiresAt:   e.ExpiresAt,
		Scope:       scopeForEntry(e),
		CachedAt:    e.CachedAt,
		Flow:        e.Flow,
	}
}
