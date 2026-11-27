// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// clusterServer is a fake OpenShift API server for tests. It serves OAuth
// discovery, whoami, and the TokenRequest endpoint.
type clusterServer struct {
	mu           sync.RWMutex
	srv          *httptest.Server
	authzURL     string
	whoamiName   string
	whoamiStatus int
	whoamiHook   func()
	saToken      string
	saStatus     int
	saHook       func()
}

// newClusterServer starts a fake API server with sensible defaults.
func newClusterServer(t *testing.T) *clusterServer {
	t.Helper()
	cs := &clusterServer{
		whoamiName:   "jane.doe",
		whoamiStatus: http.StatusOK,
		saToken:      "sa-minted-token",
		saStatus:     http.StatusCreated,
	}
	mux := http.NewServeMux()

	mux.HandleFunc(wellKnownPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, oauthMetadata{
			Issuer:                cs.srv.URL,
			AuthorizationEndpoint: cs.authzEndpoint(),
			TokenEndpoint:         cs.srv.URL + "/oauth/token",
		})
	})

	mux.HandleFunc(whoamiPath, func(w http.ResponseWriter, _ *http.Request) {
		cs.mu.RLock()
		hook := cs.whoamiHook
		statusCode := cs.whoamiStatus
		name := cs.whoamiName
		cs.mu.RUnlock()

		if hook != nil {
			hook()
		}
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		resp := userInfo{}
		resp.Metadata.Name = name
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, _ *http.Request) {
		cs.mu.RLock()
		hook := cs.saHook
		statusCode := cs.saStatus
		tok := cs.saToken
		cs.mu.RUnlock()

		if hook != nil {
			hook()
		}
		if statusCode != http.StatusOK && statusCode != http.StatusCreated {
			w.WriteHeader(statusCode)
			return
		}
		var resp tokenRequestResponse
		resp.Status.Token = tok
		resp.Status.ExpirationTimestamp = time.Now().Add(time.Hour)
		writeJSON(w, statusCode, resp)
	})

	cs.srv = httptest.NewServer(mux)
	cs.authzURL = cs.srv.URL + "/oauth/authorize"
	t.Cleanup(cs.srv.Close)
	return cs
}

func (cs *clusterServer) authzEndpoint() string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if cs.authzURL != "" {
		return cs.authzURL
	}
	return "https://oauth.example.test/oauth/authorize"
}

func (cs *clusterServer) url() string { return cs.srv.URL }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fakeBrowser returns a browserOpener that simulates a successful implicit-grant
// login by asynchronously POSTing the URL-encoded fragment parameters to the
// loopback callback server's /token endpoint, matching oauth-helpers' bridge JS.
func fakeBrowser(token string, expiresIn int) browserOpener {
	return func(ctx context.Context, rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		q := u.Query()
		redirect := q.Get("redirect_uri")
		payload := map[string]string{
			"access_token": token,
			"token_type":   "Bearer",
			"state":        q.Get("state"),
		}
		if expiresIn > 0 {
			payload["expires_in"] = fmt.Sprintf("%d", expiresIn)
		}
		reqCtx := context.WithoutCancel(ctx)
		go func() {
			cbCtx, cancel := context.WithTimeout(reqCtx, 5*time.Second)
			defer cancel()
			_ = postCallback(cbCtx, redirect, payload)
		}()
		return nil
	}
}

// postCallback POSTs form-encoded implicit-grant fragment parameters to the
// loopback callback server's /token endpoint, mirroring oauth-helpers'
// implicitBridgeScript.
func postCallback(ctx context.Context, callbackURL string, payload map[string]string) error {
	parsed, err := url.Parse(callbackURL)
	if err != nil {
		return err
	}
	origin := parsed.Scheme + "://" + parsed.Host

	form := make(url.Values, len(payload))
	for k, v := range payload {
		form.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// errorBrowser returns a browserOpener that simulates the OAuth server denying
// the request with a state-matched implicit-grant error redirect.
func errorBrowser() browserOpener {
	return func(ctx context.Context, rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		q := u.Query()
		redirect := q.Get("redirect_uri")
		state := q.Get("state")
		reqCtx := context.WithoutCancel(ctx)
		go func() {
			cbCtx, cancel := context.WithTimeout(reqCtx, 5*time.Second)
			defer cancel()
			_ = postCallback(cbCtx, redirect, map[string]string{
				"error":             "access_denied",
				"error_description": "user denied access",
				"state":             state,
			})
		}()
		return nil
	}
}

// newWiredPlugin builds a configured Plugin pointed at the fake cluster, with
// the fake browser and a short login timeout.
func newWiredPlugin(t *testing.T, cs *clusterServer, browser browserOpener) *Plugin {
	t.Helper()
	p := &Plugin{
		http:    cs.srv.Client(),
		browser: browser,
	}
	if err := p.ConfigureAuthHandler(context.Background(), HandlerName, mustSettings(t, cs.url())); err != nil {
		t.Fatalf("configure: %v", err)
	}
	p.config.LoginTimeout = 3 * time.Second
	return p
}

// mustSettings builds a ProviderConfig with the apiServerUrl setting.
func mustSettings(t *testing.T, apiServerURL string) (cfg sdkplugin.ProviderConfig) {
	t.Helper()
	raw, err := json.Marshal(apiServerURL)
	if err != nil {
		t.Fatalf("marshal setting: %v", err)
	}
	cfg.Settings = map[string]json.RawMessage{"apiServerUrl": raw}
	return cfg
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
