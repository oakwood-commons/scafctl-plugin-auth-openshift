// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// callbackPath is the loopback OAuth redirect path registered with
	// OpenShift's public CLI OAuth client.
	callbackPath = "/callback"

	// callbackShutdownTimeout bounds graceful draining of the localhost callback
	// HTTP response after the login outcome is settled.
	callbackShutdownTimeout = 5 * time.Second
)

// browserOpener opens a URL in the user's browser. It is a field on Plugin so
// tests can substitute a fake browser without launching external processes.
type browserOpener func(ctx context.Context, rawURL string) error

type browserPreferenceKeyType struct{}

func withBrowserPreference(ctx context.Context, browser string) context.Context {
	return context.WithValue(ctx, browserPreferenceKeyType{}, browser)
}

func browserPreferenceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(browserPreferenceKeyType{}).(string)
	return v
}

// defaultBrowserOpener opens rawURL using oauth-helpers, honoring any explicit
// browser preference (--browser / auth.browser), $BROWSER, and OS default
// fallback while logging fallback warnings through logr.
func defaultBrowserOpener(ctx context.Context, rawURL string) error {
	return oauth.OpenBrowserWithPreference(
		ctx,
		rawURL,
		browserPreferenceFromContext(ctx),
		oauth.WithWarningHandler(func(msg string) {
			logr.FromContextOrDiscard(ctx).V(0).Info(sanitizeUntrustedText(msg, 512))
		}),
	)
}

// webLoginResult is the credential captured from the OAuth implicit-grant
// browser flow.
type webLoginResult struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time
}

// webLoginParams bundles the inputs for runWebLogin.
type webLoginParams struct {
	Config        *Config
	Metadata      *oauthMetadata
	OpenBrowser   browserOpener
	Browser       string
	CallbackPages *sdkplugin.AuthCallbackPages
	// Commit runs after a valid token arrives from the callback server and
	// before Complete(true) releases the final HTML page to the browser. If
	// Commit returns an error, Complete(false) is called so the browser renders
	// the failure page instead of a false success message.
	Commit func(ctx context.Context, res *webLoginResult) error
}

// startImplicitCallback starts the oauth-helpers implicit-grant loopback server
// configured with deferred completion and optional host-supplied Blueprint
// callback pages.
func startImplicitCallback(ctx context.Context, host string, port int, state string, pages *sdkplugin.AuthCallbackPages) (*oauth.CallbackServer, error) {
	normHost := normalizeCallbackHost(host)
	if !isLoopbackHost(normHost) {
		return nil, fmt.Errorf("callback host %q is not a loopback address; refusing to expose the OAuth token relay on a non-loopback interface", sanitizeUntrustedText(host, 64))
	}

	opts := []oauth.CallbackOption{
		oauth.WithCallbackHost(normHost),
		oauth.WithCallbackPath(callbackPath),
		oauth.WithDeferredCompletion(),
	}
	if pages != nil {
		opts = append(opts, oauth.WithCallbackPages(oauth.CallbackPages{
			SuccessHTML: pages.SuccessHTML,
			FailureHTML: pages.FailureHTML,
		}))
	}

	cs, err := oauth.StartImplicitCallbackServer(ctx, port, state, opts...)
	if err != nil {
		return nil, fmt.Errorf("start loopback callback listener: %w", err)
	}
	return cs, nil
}

// runWebLogin performs the OpenShift OAuth implicit-grant browser flow:
// it validates the cluster's authorization endpoint, starts a loopback callback
// server bound to caller ctx, opens the user's preferred or default browser
// under a timeout-bounded context, waits up to LoginTimeout for the callback
// token, runs p.Commit under its own post-callback deadline (so completing just
// before LoginTimeout cannot race Complete(true) against an expired wait
// context), and settles + drains the callback server.
func runWebLogin(ctx context.Context, p webLoginParams) (*webLoginResult, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	cfg := p.Config

	validAuthzEndpoint, err := validateAuthorizationEndpoint(p.Metadata.AuthorizationEndpoint, cfg.APIServerURL)
	if err != nil {
		return nil, err
	}

	state, err := randomState()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	timeout := cfg.LoginTimeout
	if timeout <= 0 {
		timeout = DefaultLoginTimeout
	}

	callbackServer, err := startImplicitCallback(ctx, cfg.CallbackHost, cfg.CallbackPort, state, p.CallbackPages)
	if err != nil {
		return nil, err
	}

	drained := false
	drainCallbackServer := func() {
		if drained {
			return
		}
		drained = true
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), callbackShutdownTimeout)
		defer shutdownCancel()
		_ = callbackServer.Shutdown(shutdownCtx)
	}
	defer drainCallbackServer()

	authURL := buildAuthorizeURL(validAuthzEndpoint, cfg.OAuthClientID, callbackServer.RedirectURI, state)
	safeAuthURL := sanitizeUntrustedText(authURL, 2048)
	lgr.V(1).Info("opening browser for OpenShift OAuth login", "url", safeAuthURL, "browser", sanitizeUntrustedText(p.Browser, 64))
	if p.OpenBrowser != nil {
		openCtx, cancelOpen := context.WithTimeout(withBrowserPreference(ctx, p.Browser), timeout)
		openErr := p.OpenBrowser(openCtx, authURL)
		cancelOpen()
		if openErr != nil && ctx.Err() == nil {
			lgr.V(0).Info("failed to open browser; open this URL manually", "url", safeAuthURL, "error", sanitizeUntrustedText(openErr.Error(), 256))
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case cbRes := <-callbackServer.ResultChan():
		timer.Stop()
		if cbRes.Err != nil {
			drainCallbackServer()
			return nil, fmt.Errorf("authorization failed: %w", cbRes.Err)
		}
		res := &webLoginResult{
			AccessToken: cbRes.AccessToken,
			TokenType:   firstNonEmpty(cbRes.TokenType, "Bearer"),
			ExpiresAt:   expiryFromExpiresIn(cbRes.ExpiresIn),
		}
		if p.Commit != nil {
			commitCtx, cancelCommit := context.WithTimeout(ctx, DefaultHTTPTimeout)
			commitErr := p.Commit(commitCtx, res)
			cancelCommit()
			if commitErr != nil {
				callbackServer.Complete(false)
				drainCallbackServer()
				return nil, commitErr
			}
		}
		callbackServer.Complete(true)
		drainCallbackServer()
		return res, nil

	case <-timer.C:
		callbackServer.Complete(false)
		drainCallbackServer()
		return nil, fmt.Errorf("web login: no response from browser within %s", timeout)

	case <-ctx.Done():
		callbackServer.Complete(false)
		drainCallbackServer()
		return nil, fmt.Errorf("web login: cancelled: %w", ctx.Err())
	}
}

// buildAuthorizeURL constructs the OpenShift OAuth authorize URL for the
// implicit grant (response_type=token) using structured query encoding so any
// existing non-reserved query parameters on authzEndpoint are preserved cleanly.
func buildAuthorizeURL(authzEndpoint, clientID, redirectURI, state string) string {
	u, err := url.Parse(authzEndpoint)
	if err != nil {
		return fmt.Sprintf(
			"%s?client_id=%s&response_type=token&redirect_uri=%s&state=%s",
			authzEndpoint,
			queryEscape(clientID),
			queryEscape(redirectURI),
			queryEscape(state),
		)
	}
	u.Fragment = ""
	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("response_type", "token")
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// expiryFromExpiresIn converts an OAuth expires_in (seconds) string into an
// absolute expiry time. A missing or invalid value yields a zero time, which
// callers treat as "unknown".
func expiryFromExpiresIn(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	secs, err := strconv.Atoi(s)
	if err != nil || secs <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(secs) * time.Second)
}

// randomState returns a cryptographically random hex string for CSRF
// protection.
func randomState() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// isLoopbackHost reports whether host is a loopback target safe to bind the
// OAuth callback relay to. It accepts "localhost" and any loopback IP literal.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// firstNonEmpty returns the first non-empty string from its arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
