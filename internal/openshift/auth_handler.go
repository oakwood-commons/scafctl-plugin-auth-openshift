// Package openshift implements the openshift auth handler plugin.
//
// The handler performs the OpenShift OAuth browser web-login (implicit grant)
// and holds the resulting credential in the host secret store. It can also mint
// scoped service-account tokens via the Kubernetes TokenRequest API. All
// cluster- and org-specific values are configuration-driven so the handler
// stays generic.
package openshift

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

// Compile-time assertion that Plugin satisfies sdkplugin.AuthHandlerPlugin.
var _ sdkplugin.AuthHandlerPlugin = (*Plugin)(nil)

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	mu                 sync.RWMutex
	cfg                sdkplugin.ProviderConfig
	config             *Config
	cachedHostClient   *sdkplugin.HostServiceClient
	http               httpDoer
	browser            browserOpener
	stdHTTPClient      *http.Client
	insecureHTTPClient *http.Client
	profileLocks       sync.Map
	lastLoginUnixNano  atomic.Int64
}

// nextLoginTimestamp returns a UTC timestamp guaranteed to advance monotonically
// across Login commits on this Plugin instance so CachedAt uniquely identifies
// each login session even if Logout and re-Login reuse the same bearer string.
func (p *Plugin) nextLoginTimestamp() time.Time {
	ns := time.Now().UTC().UnixNano()
	for {
		prev := p.lastLoginUnixNano.Load()
		next := ns
		if next <= prev {
			next = prev + 1
		}
		if p.lastLoginUnixNano.CompareAndSwap(prev, next) {
			return time.Unix(0, next).UTC()
		}
	}
}

// profileLock returns the profile-scoped RWMutex coordinating in-process
// credential reads, writes, migrations, purges, and logouts without blocking
// other profiles or holding locks across external HTTP or browser I/O.
// p.mu is never acquired while a profileLock is held.
func (p *Plugin) profileLock(ctx context.Context) *sync.RWMutex {
	profile := auth.ProfileFromContext(ctx)
	if v, ok := p.profileLocks.Load(profile); ok {
		return v.(*sync.RWMutex)
	}
	mu := &sync.RWMutex{}
	actual, _ := p.profileLocks.LoadOrStore(profile, mu)
	return actual.(*sync.RWMutex)
}

// attachRequestSettings ensures per-RPC request settings carried on a request
// struct are also visible via sdkplugin.RequestSettingsFromContext(ctx) when
// Plugin methods are called directly without gRPC server wrapping.
func attachRequestSettings(ctx context.Context, reqSettings map[string]json.RawMessage) context.Context {
	if _, ok := sdkplugin.RequestSettingsFromContext(ctx); !ok && reqSettings != nil {
		return sdkplugin.WithRequestSettings(ctx, reqSettings)
	}
	return ctx
}

// hostClient returns the per-RPC HostServiceClient from ctx, falling back to
// any client cached during ConfigureAuthHandler.
func (p *Plugin) hostClient(ctx context.Context) *sdkplugin.HostServiceClient {
	if hc := sdkplugin.HostClientFromContext(ctx); hc != nil {
		return hc
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cachedHostClient
}

// callbackPages returns a defensive snapshot of any host-supplied Blueprint
// callback HTML pages configured on the plugin.
func (p *Plugin) callbackPages() *sdkplugin.AuthCallbackPages {
	p.mu.RLock()
	pages := p.cfg.AuthCallbackPages
	p.mu.RUnlock()
	if pages == nil {
		return nil
	}
	cp := &sdkplugin.AuthCallbackPages{}
	if len(pages.SuccessHTML) > 0 {
		cp.SuccessHTML = bytes.Clone(pages.SuccessHTML)
	}
	if len(pages.FailureHTML) > 0 {
		cp.FailureHTML = bytes.Clone(pages.FailureHTML)
	}
	return cp
}

// getBrowserOpener returns the configured browser opener (or
// defaultBrowserOpener when unset).
func (p *Plugin) getBrowserOpener() browserOpener {
	p.mu.RLock()
	b := p.browser
	p.mu.RUnlock()
	if b != nil {
		return b
	}
	return defaultBrowserOpener
}

// httpClientForConfig returns a test-injected httpDoer when set, or a bounded
// reused *http.Client matching cfg.InsecureSkipTLSVerify so per-RPC settings
// never bleed TLS verification state across profiles or recreate transports per
// call.
func (p *Plugin) httpClientForConfig(cfg *Config) httpDoer {
	insecure := cfg != nil && cfg.InsecureSkipTLSVerify

	p.mu.RLock()
	if p.http != nil {
		injected := p.http
		p.mu.RUnlock()
		return injected
	}
	if insecure && p.insecureHTTPClient != nil {
		c := p.insecureHTTPClient
		p.mu.RUnlock()
		return c
	}
	if !insecure && p.stdHTTPClient != nil {
		c := p.stdHTTPClient
		p.mu.RUnlock()
		return c
	}
	p.mu.RUnlock()

	created := newHTTPClient(DefaultHTTPTimeout, insecure)

	var discard *http.Client
	var chosen httpDoer

	p.mu.Lock()
	switch {
	case p.http != nil:
		discard = created
		chosen = p.http
	case insecure:
		if p.insecureHTTPClient == nil {
			p.insecureHTTPClient = created
		} else {
			discard = created
		}
		chosen = p.insecureHTTPClient
	default:
		if p.stdHTTPClient == nil {
			p.stdHTTPClient = created
		} else {
			discard = created
		}
		chosen = p.stdHTTPClient
	}
	p.mu.Unlock()

	closeHTTPClientIdle(discard)
	return chosen
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
// state. Managed HTTP clients depend solely on DefaultHTTPTimeout and the
// per-call InsecureSkipTLSVerify boolean, so existing pooled transports are
// preserved across ApplyOverrides calls and closed only on StopAuthHandler.
func (p *Plugin) ConfigureAuthHandler(ctx context.Context, handlerName string, cfg sdkplugin.ProviderConfig) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}

	config := DefaultConfig()
	if err := config.applySettings(cfg.Settings); err != nil {
		return fmt.Errorf("apply handler settings: %w", err)
	}
	config.normalize()

	storedCfg := cfg
	if cfg.Settings != nil {
		clonedSettings := make(map[string]json.RawMessage, len(cfg.Settings))
		for k, v := range cfg.Settings {
			clonedSettings[k] = bytes.Clone(v)
		}
		storedCfg.Settings = clonedSettings
	}
	if cfg.AuthCallbackPages != nil {
		storedCfg.AuthCallbackPages = &sdkplugin.AuthCallbackPages{
			SuccessHTML: bytes.Clone(cfg.AuthCallbackPages.SuccessHTML),
			FailureHTML: bytes.Clone(cfg.AuthCallbackPages.FailureHTML),
		}
	}

	p.mu.Lock()
	p.cfg = storedCfg
	p.config = config
	if hc := sdkplugin.HostClientFromContext(ctx); hc != nil {
		p.cachedHostClient = hc
	}
	if p.browser == nil {
		p.browser = defaultBrowserOpener
	}
	p.mu.Unlock()

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
		return nil, fmt.Errorf("unsupported flow %q: openshift supports %q", sanitizeUntrustedText(string(req.Flow), 64), auth.FlowInteractive)
	}

	ctx = attachRequestSettings(ctx, req.Settings)
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx, req.Timeout)
	if err != nil {
		return nil, fmt.Errorf("openshift: %w", err)
	}

	host := p.hostClient(ctx)
	if host == nil {
		return nil, fmt.Errorf("openshift: secret store unavailable")
	}

	// Honor a host-requested loopback callback port (advertised via
	// auth.CapCallbackPort). Zero keeps the ephemeral-port default. The host
	// validates the range before forwarding, but guard anyway so an out-of-range
	// value falls back to an ephemeral port rather than failing to listen.
	if req.CallbackPort >= 1024 && req.CallbackPort <= 65535 {
		cfg.CallbackPort = req.CallbackPort
		lgr.V(1).Info("using host-requested OAuth callback port", "port", req.CallbackPort)
	}

	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))

	apiServer, clientID, err := resolveTargetCluster(ctx, cfg, host, prefix, req.Hostname, false)
	if err != nil {
		return nil, fmt.Errorf("openshift: %w", err)
	}
	if apiServer == "" {
		return nil, fmt.Errorf("api server URL is required; set it in handler config, pass --hostname, or %s", strings.Join(apiServerEnvVars, "/"))
	}
	cfg.APIServerURL = apiServer
	if clientID != "" && !cfg.hasClientIDOverride {
		cfg.OAuthClientID = clientID
	}

	httpClient := p.httpClientForConfig(cfg)
	meta, err := discoverOAuthMetadata(ctx, httpClient, apiServer)
	if err != nil {
		return nil, fmt.Errorf("openshift: %w", err)
	}

	var storedEntry *cacheEntry
	_, err = runWebLogin(ctx, webLoginParams{
		Config:        cfg,
		Metadata:      meta,
		OpenBrowser:   p.getBrowserOpener(),
		Browser:       req.Browser,
		CallbackPages: p.callbackPages(),
		Commit: func(commitCtx context.Context, res *webLoginResult) error {
			whoamiCtx, cancelWhoami := context.WithTimeout(commitCtx, defaultWhoamiTimeout)
			username := resolveUsername(whoamiCtx, httpClient, apiServer, res.AccessToken)
			cancelWhoami()

			mu := p.profileLock(ctx)
			mu.Lock()
			now := p.nextLoginTimestamp()
			expiresAt := res.ExpiresAt
			if expiresAt.IsZero() {
				expiresAt = now.Add(defaultAssumedTokenTTL)
			}
			entry := &cacheEntry{
				AccessToken: res.AccessToken,
				TokenType:   res.TokenType,
				ExpiresAt:   expiresAt,
				CachedAt:    now,
				Flow:        auth.FlowInteractive,
				Kind:        kindUser,
				APIServer:   apiServer,
				Username:    username,
			}
			storeErr := cacheSet(commitCtx, host, userTokenKey(prefix, apiServer), entry)
			if storeErr == nil {
				cacheDeleteLegacyUserKeys(commitCtx, lgr, host, prefix, apiServer)
				// Clear any service-account tokens cached under a previous user
				// session for this cluster so a new user never inherits them.
				cacheClearClusterSATokens(commitCtx, lgr, host, prefix, apiServer)
				if activeErr := setActiveCluster(commitCtx, host, prefix, apiServer); activeErr != nil {
					lgr.V(1).Info("failed to record active cluster (continuing)", "error", activeErr.Error())
				}
			}
			mu.Unlock()

			if storeErr != nil {
				return fmt.Errorf("persist token: %w", storeErr)
			}
			storedEntry = entry
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("openshift: web login: %w", err)
	}

	lgr.V(1).Info("openshift login completed", "user", storedEntry.Username, "apiServer", apiServer)
	return &sdkplugin.LoginResponse{
		Claims:    claimsFromEntry(storedEntry, meta.Issuer),
		ExpiresAt: responseExpiresAt(storedEntry),
	}, nil
}

// Logout clears cached openshift credentials. An empty req.Hostname clears
// every cluster for the profile; a hostname (advertised via
// auth.CapHostname / auth.CapInstanceHostname) clears just that cluster's user
// and service-account tokens.
func (p *Plugin) Logout(ctx context.Context, handlerName string, req sdkplugin.LogoutRequest) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	lgr := logr.FromContextOrDiscard(ctx)
	host := p.hostClient(ctx)
	if host == nil {
		return fmt.Errorf("openshift: secret store unavailable")
	}

	cfg, err := p.effectiveConfig(ctx, 0)
	if err != nil {
		return fmt.Errorf("openshift: %w", err)
	}

	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))
	mu := p.profileLock(ctx)

	if req.Hostname != "" {
		apiServer, _, resolveErr := cfg.resolveCluster(req.Hostname)
		if resolveErr != nil {
			return fmt.Errorf("openshift: %w", resolveErr)
		}
		mu.Lock()
		clearErr := cacheClearCluster(ctx, lgr, host, prefix, apiServer)
		mu.Unlock()
		if clearErr != nil {
			return fmt.Errorf("openshift: clear cluster credentials: %w", clearErr)
		}
		return nil
	}

	mu.Lock()
	clearErr := cacheClearAll(ctx, lgr, host, prefix)
	mu.Unlock()
	if clearErr != nil {
		return fmt.Errorf("openshift: clear credentials: %w", clearErr)
	}
	return nil
}

// GetStatus reports current authentication status without side effects. A
// req.Hostname (advertised via auth.CapInstanceHostname) selects the cluster to
// report; otherwise it falls back to the configured cluster, the active
// cluster, and finally (when no single cluster is pinned in config) any other
// live user session for the profile so multi-cluster status views stay visible.
func (p *Plugin) GetStatus(ctx context.Context, handlerName string, req sdkplugin.StatusRequest) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	ctx = attachRequestSettings(ctx, req.Settings)
	cfg, err := p.effectiveConfig(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("openshift: %w", err)
	}

	host := p.hostClient(ctx)
	if host == nil {
		return &auth.Status{Authenticated: false, Reason: "secret store unavailable"}, nil
	}

	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))

	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	apiServer, _, err := resolveTargetCluster(ctx, cfg, host, prefix, req.Hostname, true)
	if err != nil {
		return &auth.Status{Authenticated: false, Reason: err.Error()}, nil
	}

	var entry *cacheEntry
	if apiServer != "" {
		entry, _, err = cacheGetUser(ctx, host, prefix, apiServer)
		if err != nil {
			return &auth.Status{Authenticated: false, Reason: err.Error()}, nil
		}
	}

	// When no explicit hostname or configured apiServerUrl pinned a single
	// cluster and the active cluster is absent or expired, check whether
	// another logged-in cluster for this profile is still usable so host-side
	// multi-cluster status expansion (statusrows.Expand) does not short-circuit.
	if (entry == nil || !entry.isUsable()) && req.Hostname == "" && cfg.APIServerURL == "" {
		if fallback := findFallbackUserEntry(ctx, host, prefix); fallback != nil {
			entry = fallback
			apiServer = canonicalClusterKey(fallback.APIServer)
		}
	}

	if apiServer == "" || entry == nil {
		return &auth.Status{Authenticated: false, Reason: "not logged in"}, nil
	}
	if !entry.isUsable() {
		return &auth.Status{Authenticated: false, Reason: "token expired"}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims:        claimsFromEntry(entry, ""),
		ExpiresAt:     entry.effectiveExpiresAt(),
		IdentityType:  auth.IdentityTypeUser,
		Flow:          auth.FlowInteractive,
		Hostname:      apiServer,
	}, nil
}

// GetToken returns a usable token. With an empty/"user" scope it returns the
// held user OAuth token. When the scope encodes a service account (see
// classifyTokenScope) it mints (and caches) a scoped service-account token via
// the TokenRequest API; malformed non-empty scopes fail closed.
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	ctx = attachRequestSettings(ctx, req.Settings)
	cfg, err := p.effectiveConfig(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("openshift: %w", err)
	}

	sa, isSAScope, scopeErr := classifyTokenScope(req.Scope)
	if scopeErr != nil {
		return nil, fmt.Errorf("openshift: %w", scopeErr)
	}

	host := p.hostClient(ctx)
	if host == nil {
		return nil, fmt.Errorf("secret store unavailable")
	}

	prefix := profileKeyPrefix(auth.ProfileFromContext(ctx))

	if isSAScope {
		return p.getServiceAccountToken(ctx, cfg, host, prefix, sa, req)
	}
	return p.getUserToken(ctx, cfg, host, prefix, req)
}

// getUserToken resolves the target cluster and reads the held user OAuth token
// under a profile read lock, upgrading to the profile write lock only when
// legacy non-canonical user-token keys need migration.
func (p *Plugin) getUserToken(ctx context.Context, cfg *Config, host *sdkplugin.HostServiceClient, prefix string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	mu := p.profileLock(ctx)
	mu.RLock()
	apiServer, _, resolveErr := resolveTargetCluster(ctx, cfg, host, prefix, req.Hostname, true)
	if resolveErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("openshift: %w", resolveErr)
	}
	if apiServer == "" {
		mu.RUnlock()
		return nil, fmt.Errorf("api server URL is required; set it in handler config, pass --hostname, or %s", strings.Join(apiServerEnvVars, "/"))
	}
	entry, legacyKeys, err := cacheGetUser(ctx, host, prefix, apiServer)
	mu.RUnlock()
	if err != nil {
		return nil, err
	}
	if entry != nil && len(legacyKeys) > 0 {
		mu.Lock()
		cacheMigrateLegacyUser(ctx, logr.FromContextOrDiscard(ctx), host, prefix, apiServer)
		entry, _, err = cacheGetUser(ctx, host, prefix, apiServer)
		mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	if entry == nil || entry.AccessToken == "" {
		return nil, fmt.Errorf("not authenticated")
	}
	if !entry.isUsableFor(req.MinValidFor) {
		return nil, fmt.Errorf("token expired: run login again")
	}
	return tokenResponseFromEntry(entry), nil
}

// getServiceAccountToken returns a cached SA token bound to the current user
// session or mints a fresh one. Network I/O (TokenRequest API) runs outside the
// profile lock, and the parent user session is re-verified in constant time
// under the profile write lock before caching or returning the minted token so
// neither a concurrent Logout nor an ABA re-Login can store or hand out a
// mismatched SA token.
func (p *Plugin) getServiceAccountToken(ctx context.Context, cfg *Config, host *sdkplugin.HostServiceClient, prefix string, sa saScope, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	mu := p.profileLock(ctx)
	mu.RLock()
	apiServer, _, resolveErr := resolveTargetCluster(ctx, cfg, host, prefix, req.Hostname, true)
	if resolveErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("openshift: %w", resolveErr)
	}
	if apiServer == "" {
		mu.RUnlock()
		return nil, fmt.Errorf("api server URL is required; set it in handler config, pass --hostname, or %s", strings.Join(apiServerEnvVars, "/"))
	}

	saKey := saTokenKey(prefix, apiServer, sa.Namespace, sa.ServiceAccount, sa.Audience)

	user, legacyKeys, err := cacheGetUser(ctx, host, prefix, apiServer)
	if err != nil {
		mu.RUnlock()
		return nil, err
	}
	var bearerToken, parentHash string
	var capturedCachedAt time.Time
	if len(legacyKeys) > 0 {
		mu.RUnlock()
		mu.Lock()
		cacheMigrateLegacyUser(ctx, logr.FromContextOrDiscard(ctx), host, prefix, apiServer)
		user, _, err = cacheGetUser(ctx, host, prefix, apiServer)
		if err != nil || user == nil || !user.isUsable() {
			mu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("not authenticated: log in before minting a service-account token")
		}
		bearerToken = user.AccessToken
		parentHash = fingerprintHash(bearerToken)
		capturedCachedAt = user.CachedAt
		if !req.ForceRefresh {
			if cached, cerr := cacheGet(ctx, host, saKey); cerr == nil && cached != nil &&
				subtle.ConstantTimeCompare([]byte(cached.ParentTokenHash), []byte(parentHash)) == 1 &&
				cached.isUsableFor(req.MinValidFor) {
				mu.Unlock()
				return tokenResponseFromEntry(cached), nil
			}
		}
		mu.Unlock()
	} else {
		if user == nil || !user.isUsable() {
			mu.RUnlock()
			return nil, fmt.Errorf("not authenticated: log in before minting a service-account token")
		}
		bearerToken = user.AccessToken
		parentHash = fingerprintHash(bearerToken)
		capturedCachedAt = user.CachedAt
		if !req.ForceRefresh {
			if cached, cerr := cacheGet(ctx, host, saKey); cerr == nil && cached != nil &&
				subtle.ConstantTimeCompare([]byte(cached.ParentTokenHash), []byte(parentHash)) == 1 &&
				cached.isUsableFor(req.MinValidFor) {
				mu.RUnlock()
				return tokenResponseFromEntry(cached), nil
			}
		}
		mu.RUnlock()
	}

	minted, err := mintServiceAccountToken(ctx, p.httpClientForConfig(cfg), mintSAParams{
		APIServerURL:   apiServer,
		BearerToken:    bearerToken,
		Namespace:      sa.Namespace,
		ServiceAccount: sa.ServiceAccount,
		Audience:       sa.Audience,
	})
	if err != nil {
		return nil, err
	}
	minted.Flow = auth.FlowInteractive
	minted.ParentTokenHash = parentHash

	mu.Lock()
	curUser, _, curErr := cacheGetUser(ctx, host, prefix, apiServer)
	sessionValid := curErr == nil && curUser != nil && curUser.isUsable() &&
		curUser.CachedAt.Equal(capturedCachedAt) &&
		subtle.ConstantTimeCompare([]byte(fingerprintHash(curUser.AccessToken)), []byte(minted.ParentTokenHash)) == 1 &&
		subtle.ConstantTimeCompare([]byte(curUser.AccessToken), []byte(bearerToken)) == 1
	if sessionValid {
		if setErr := cacheSet(ctx, host, saKey, minted); setErr != nil {
			logr.FromContextOrDiscard(ctx).V(1).Info("failed to cache minted token (continuing)", "error", setErr.Error())
		}
	}
	mu.Unlock()

	if !sessionValid {
		if curErr != nil {
			return nil, curErr
		}
		return nil, fmt.Errorf("not authenticated: user session changed or expired during service-account token request")
	}

	return tokenResponseFromEntry(minted), nil
}

// ListCachedTokens returns information about cached tokens for the request
// profile.
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	host := p.hostClient(ctx)
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()
	return cacheList(ctx, host, profileKeyPrefix(auth.ProfileFromContext(ctx)))
}

// PurgeExpiredTokens removes expired tokens from the cache for the request
// profile under the profile write lock so read/delete cannot race with
// concurrent in-process token writes.
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}
	host := p.hostClient(ctx)
	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()
	return cachePurgeExpired(ctx, host, profileKeyPrefix(auth.ProfileFromContext(ctx)))
}

// StopAuthHandler performs cleanup for the named handler, closing any idle
// HTTP transport connections.
func (p *Plugin) StopAuthHandler(_ context.Context, handlerName string) error {
	if handlerName != "" && handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	p.mu.Lock()
	stdClient := p.stdHTTPClient
	insecureClient := p.insecureHTTPClient
	p.stdHTTPClient = nil
	p.insecureHTTPClient = nil
	p.cachedHostClient = nil
	p.mu.Unlock()

	closeHTTPClientIdle(stdClient)
	closeHTTPClientIdle(insecureClient)
	return nil
}

// DetectAvailableFlows reports which auth flows are usable in the current
// environment, honoring per-RPC request settings when provided.
func (p *Plugin) DetectAvailableFlows(ctx context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	if _, err := p.effectiveConfig(ctx, 0); err != nil {
		return nil, fmt.Errorf("openshift: %w", err)
	}
	return []sdkplugin.FlowAvailability{
		{Flow: auth.FlowInteractive, Available: true, Reason: "browser-based OAuth login"},
	}, nil
}

// resolveTargetCluster selects and canonicalizes the target cluster API server
// URL using identical precedence and normalization rules across Login,
// GetStatus, and GetToken:
//  1. Explicit per-request hostname (alias or direct URL/host).
//  2. Configured or env-resolved cfg.APIServerURL.
//  3. Profile's active cluster (when allowActiveFallback is true).
func resolveTargetCluster(ctx context.Context, cfg *Config, host *sdkplugin.HostServiceClient, prefix, reqHostname string, allowActiveFallback bool) (apiServer, oauthClientID string, err error) {
	if reqHostname != "" {
		return cfg.resolveCluster(reqHostname)
	}
	if cfg.APIServerURL != "" {
		normalized, nerr := normalizeEndpoint(cfg.APIServerURL)
		if nerr != nil {
			return "", "", nerr
		}
		return normalized, "", nil
	}
	if allowActiveFallback && host != nil {
		if active := getActiveCluster(ctx, host, prefix); active != "" {
			normalized, nerr := normalizeEndpoint(active)
			if nerr != nil {
				return "", "", nerr
			}
			return normalized, "", nil
		}
	}
	return "", "", nil
}

// effectiveConfig returns a per-RPC Config copy without mutating p.config.
// When RequestSettingsFromContext(ctx) is present (per-command --profile or
// solution settings), settings are decoded onto clean defaults so another
// profile's p.config values never bleed across profiles. When absent, p.config
// is deep-copied.
func (p *Plugin) effectiveConfig(ctx context.Context, timeout time.Duration) (*Config, error) {
	var cfg *Config
	if reqSettings, ok := sdkplugin.RequestSettingsFromContext(ctx); ok {
		cfg = DefaultConfig()
		if err := cfg.applySettings(reqSettings); err != nil {
			return nil, fmt.Errorf("apply request settings: %w", err)
		}
	} else {
		p.mu.RLock()
		cfg = p.config.clone()
		p.mu.RUnlock()
	}

	if cfg.APIServerURL == "" {
		cfg.APIServerURL = apiServerFromEnv()
	}
	if timeout > 0 {
		cfg.LoginTimeout = timeout
	}
	cfg.normalize()
	return cfg, nil
}

// apiServerFromEnv resolves the API server URL from environment variables.
func apiServerFromEnv() string {
	for _, key := range apiServerEnvVars {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return canonicalizeOrTrimURL(v)
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
		ExpiresAt: e.effectiveExpiresAt(),
		IssuedAt:  e.CachedAt,
	}
}

// responseExpiresAt returns the fixed expiry timestamp for gRPC LoginResponse
// and TokenResponse messages. Entries captured via Login or cacheSet always
// carry a non-zero effectiveExpiresAt anchored to capture/cache time; the
// fallback guards only uncached in-memory test structs with zero timestamps.
func responseExpiresAt(e *cacheEntry) time.Time {
	if exp := e.effectiveExpiresAt(); !exp.IsZero() {
		return exp
	}
	return time.Now().Add(defaultAssumedTokenTTL)
}

// tokenResponseFromEntry adapts a cached entry to a plugin TokenResponse.
func tokenResponseFromEntry(e *cacheEntry) *sdkplugin.TokenResponse {
	return &sdkplugin.TokenResponse{
		AccessToken: e.AccessToken,
		TokenType:   firstNonEmpty(e.TokenType, "Bearer"),
		ExpiresAt:   responseExpiresAt(e),
		Scope:       scopeForEntry(e),
		CachedAt:    e.CachedAt,
		Flow:        e.Flow,
	}
}
