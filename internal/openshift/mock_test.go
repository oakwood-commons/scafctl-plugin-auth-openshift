// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// clusterServer is a fake OpenShift API server for tests. It serves OAuth
// discovery, whoami, and the TokenRequest endpoint.
type clusterServer struct {
	srv          *httptest.Server
	authzURL     string
	whoamiName   string
	whoamiStatus int
	saToken      string
	saStatus     int
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
		if cs.whoamiStatus != http.StatusOK {
			w.WriteHeader(cs.whoamiStatus)
			return
		}
		resp := userInfo{}
		resp.Metadata.Name = cs.whoamiName
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, _ *http.Request) {
		if cs.saStatus != http.StatusOK && cs.saStatus != http.StatusCreated {
			w.WriteHeader(cs.saStatus)
			return
		}
		var resp tokenRequestResponse
		resp.Status.Token = cs.saToken
		resp.Status.ExpirationTimestamp = time.Now().Add(time.Hour)
		writeJSON(w, cs.saStatus, resp)
	})

	cs.srv = httptest.NewServer(mux)
	cs.authzURL = cs.srv.URL + "/oauth/authorize"
	t.Cleanup(cs.srv.Close)
	return cs
}

func (cs *clusterServer) authzEndpoint() string {
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
// login by POSTing the token to the callback server as a JSON body, exactly as
// the in-browser JavaScript would.
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
		return postCallback(ctx, redirect, payload)
	}
}

// postCallback POSTs a JSON callback payload to the loopback callback server,
// mirroring the fragment-extractor script the browser runs.
func postCallback(ctx context.Context, callbackURL string, payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// errorBrowser returns a browserOpener that simulates the OAuth server denying
// the request.
func errorBrowser() browserOpener {
	return func(ctx context.Context, rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		return postCallback(ctx, u.Query().Get("redirect_uri"), map[string]string{
			"error":             "access_denied",
			"error_description": "user denied access",
		})
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
