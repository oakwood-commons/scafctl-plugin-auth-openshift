// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/go-logr/logr"
)

// browserOpener opens a URL in the system browser. It is a field on Plugin so
// tests can substitute a no-op or capture the URL.
type browserOpener func(ctx context.Context, rawURL string) error

// defaultBrowserOpener launches the platform's default browser.
func defaultBrowserOpener(ctx context.Context, rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		// #nosec G204 -- rawURL is an OAuth authorize URL we constructed; the
		// command name is a constant and the URL is the single argument.
		cmd = exec.CommandContext(ctx, "open", rawURL)
	case "windows":
		// #nosec G204 -- see darwin case; constant command, constructed URL.
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		// #nosec G204 -- see darwin case; constant command, constructed URL.
		cmd = exec.CommandContext(ctx, "xdg-open", rawURL)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap the browser process so it does not linger as a zombie.
	go func() { _ = cmd.Wait() }()
	return nil
}

// webLoginResult is the credential captured from the OAuth implicit-grant
// browser flow.
type webLoginResult struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time
}

// runWebLogin performs the OpenShift OAuth implicit-grant browser flow:
// it starts a loopback callback server, opens the browser to the cluster's
// authorization endpoint, and captures the token returned in the URL fragment.
func runWebLogin(ctx context.Context, cfg *Config, meta *oauthMetadata, open browserOpener) (*webLoginResult, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	state, err := randomState()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	if !isLoopbackHost(cfg.CallbackHost) {
		return nil, fmt.Errorf("callback host %q is not a loopback address; refusing to expose the OAuth token relay on a non-loopback interface", cfg.CallbackHost)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.CallbackHost, strconv.Itoa(cfg.CallbackPort)))
	if err != nil {
		return nil, fmt.Errorf("start callback listener: %w", err)
	}
	defer func() { _ = listener.Close() }()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := buildRedirectURI(cfg.CallbackHost, port)

	resultCh := make(chan webLoginResult, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{
		Handler:           newCallbackHandler(state, resultCh, errCh),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if serveErr := srv.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			select {
			case errCh <- serveErr:
			default:
			}
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	authURL := buildAuthorizeURL(meta.AuthorizationEndpoint, cfg.OAuthClientID, redirectURI, state)
	lgr.V(1).Info("opening browser for OpenShift OAuth login", "url", authURL)
	if open != nil {
		if openErr := open(ctx, authURL); openErr != nil {
			lgr.V(0).Info("failed to open browser; open this URL manually", "url", authURL)
		}
	}

	timeout := cfg.LoginTimeout
	if timeout <= 0 {
		timeout = DefaultLoginTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-resultCh:
		return &res, nil
	case err := <-errCh:
		return nil, err
	case <-timer.C:
		return nil, fmt.Errorf("web login: no response from browser within %s", timeout)
	case <-ctx.Done():
		return nil, fmt.Errorf("web login: cancelled: %w", ctx.Err())
	}
}

// newCallbackHandler builds the HTTP handler for the loopback callback server.
//
// The implicit grant returns the token in the URL fragment, which browsers do
// not send to the server. The /callback page serves a small script that reads
// the fragment client-side and POSTs the values back as a JSON body. The token
// therefore never appears in a URL query string, server access log, or browser
// history.
func newCallbackHandler(state string, resultCh chan<- webLoginResult, errCh chan<- error) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleCallbackPost(w, r, state, resultCh, errCh)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fragmentExtractorHTML))
	})

	return mux
}

// callbackPayload is the JSON body the browser POSTs after extracting the
// implicit-grant values from the URL fragment.
type callbackPayload struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        string `json:"expires_in"`
	State            string `json:"state"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// handleCallbackPost decodes the relayed OAuth result, validates the CSRF state,
// and delivers the token (or error) to the waiting login flow.
func handleCallbackPost(w http.ResponseWriter, r *http.Request, state string, resultCh chan<- webLoginResult, errCh chan<- error) {
	const maxBody = 64 << 10 // 64 KiB is ample for an OAuth callback payload.
	var payload callbackPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&payload); err != nil {
		writeCallbackJSON(w, http.StatusBadRequest, false)
		select {
		case errCh <- fmt.Errorf("authorization failed: invalid callback payload: %w", err):
		default:
		}
		return
	}
	if payload.Error != "" {
		writeCallbackJSON(w, http.StatusBadRequest, false)
		select {
		case errCh <- fmt.Errorf("authorization failed: %s: %s", payload.Error, payload.ErrorDescription):
		default:
		}
		return
	}
	if payload.State != state {
		writeCallbackJSON(w, http.StatusBadRequest, false)
		select {
		case errCh <- fmt.Errorf("authorization failed: state mismatch (possible CSRF)"):
		default:
		}
		return
	}
	if payload.AccessToken == "" {
		writeCallbackJSON(w, http.StatusBadRequest, false)
		select {
		case errCh <- fmt.Errorf("authorization failed: no access_token in callback"):
		default:
		}
		return
	}

	res := webLoginResult{
		AccessToken: payload.AccessToken,
		TokenType:   firstNonEmpty(payload.TokenType, "Bearer"),
		ExpiresAt:   expiryFromExpiresIn(payload.ExpiresIn),
	}
	writeCallbackJSON(w, http.StatusOK, true)
	select {
	case resultCh <- res:
	default:
	}
}

// buildRedirectURI builds the loopback OAuth callback URL. It uses
// net.JoinHostPort so IPv6 loopback literals (e.g. "::1") are bracketed,
// yielding "http://[::1]:PORT/callback" rather than an invalid URL.
func buildRedirectURI(host string, port int) string {
	return fmt.Sprintf("http://%s/callback", net.JoinHostPort(host, strconv.Itoa(port)))
}

// buildAuthorizeURL constructs the OpenShift OAuth authorize URL for the
// implicit grant (response_type=token).
func buildAuthorizeURL(authzEndpoint, clientID, redirectURI, state string) string {
	return fmt.Sprintf(
		"%s?client_id=%s&response_type=token&redirect_uri=%s&state=%s",
		authzEndpoint,
		queryEscape(clientID),
		queryEscape(redirectURI),
		queryEscape(state),
	)
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

// writeCallbackJSON writes a minimal JSON acknowledgement to the browser's
// relay POST. The browser renders the user-facing message from the response.
func writeCallbackJSON(w http.ResponseWriter, status int, ok bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if ok {
		_, _ = io.WriteString(w, `{"ok":true}`)
		return
	}
	_, _ = io.WriteString(w, `{"ok":false}`)
}

// fragmentExtractorHTML reads the implicit-grant values from the URL fragment
// client-side and POSTs them as a JSON body, so the token never lands in a URL
// query string, access log, or browser history. It then clears the fragment.
const fragmentExtractorHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>scafctl login</title></head>
<body>
<p id="scafctl-msg">Completing sign-in&hellip;</p>
<script>
(function () {
  var hash = window.location.hash || "";
  if (hash.charAt(0) === "#") { hash = hash.substring(1); }
  var p = new URLSearchParams(hash);
  var payload = {};
  ["access_token", "token_type", "expires_in", "state", "error", "error_description"].forEach(function (k) {
    var v = p.get(k);
    if (v) { payload[k] = v; }
  });
  function show(msg) { document.getElementById("scafctl-msg").textContent = msg; }
  fetch(window.location.pathname, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }).then(function (r) {
    if (!r.ok) {
      show("Login failed. Return to the terminal for details.");
      return;
    }
    var secs = 30;
    (function tick() {
      show("Login successful. You can return to the terminal. This tab closes in " + secs + "s...");
      if (secs <= 0) {
        // window.close() only works on script-opened windows; re-opening self
        // first improves the odds of closing a user-navigated OAuth tab.
        try { window.open("", "_self"); window.close(); } catch (e) {}
        return;
      }
      secs -= 1;
      setTimeout(tick, 1000);
    })();
  }).catch(function () {
    show("Login failed. Return to the terminal for details.");
  }).finally(function () {
    try { history.replaceState(null, "", window.location.pathname); } catch (e) {}
  });
})();
</script>
</body></html>`
