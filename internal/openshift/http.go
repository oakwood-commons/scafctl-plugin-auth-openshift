// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpDoer is the minimal HTTP surface the handler needs. It is satisfied by
// *http.Client and by test doubles, keeping network calls injectable.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// newHTTPClient builds an *http.Client with the handler's timeout and TLS
// policy. Certificate verification is only skipped when explicitly configured.
func newHTTPClient(timeout time.Duration, insecureSkipTLSVerify bool) *http.Client {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	// Clone the stdlib default transport so proxy support (ProxyFromEnvironment)
	// and connection-pool defaults are preserved; only override TLS policy.
	transport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		transport = transport.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		//nolint:gosec // opt-in only, for dev clusters with self-signed certs
		InsecureSkipVerify: insecureSkipTLSVerify,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// getJSON performs an authenticated GET and returns the response body. The
// caller is responsible for status-code handling. bearer may be empty for
// unauthenticated requests (e.g. OAuth discovery).
func getJSON(ctx context.Context, client httpDoer, reqURL, bearer string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return doRequest(client, req)
}

// postJSON performs an authenticated POST with a JSON body.
func postJSON(ctx context.Context, client httpDoer, reqURL, bearer string, body io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return doRequest(client, req)
}

// doRequest executes req and reads the (bounded) response body.
func doRequest(client httpDoer, req *http.Request) (int, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Bound the body to guard against unexpectedly large responses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// joinURL joins a base URL with a path, collapsing duplicate slashes at the
// boundary.
func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

// queryEscape is a thin alias kept for readability at call sites that build
// OAuth authorize URLs.
func queryEscape(s string) string { return url.QueryEscape(s) }
