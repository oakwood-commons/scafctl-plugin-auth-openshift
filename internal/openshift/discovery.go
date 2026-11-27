// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// wellKnownPath is the OAuth authorization server metadata endpoint exposed by
// the OpenShift API server (RFC 8414).
const wellKnownPath = "/.well-known/oauth-authorization-server"

// reservedAuthorizeQueryKeys are OAuth authorize query parameters owned by the
// handler that an untrusted discovery document must never pre-populate.
var reservedAuthorizeQueryKeys = []string{"client_id", "response_type", "redirect_uri", "state"}

// oauthMetadata is the subset of the OAuth authorization server metadata the
// handler needs. The authorization endpoint commonly lives on a different host
// than the API server (the cluster's oauth-openshift route).
type oauthMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// validateAuthorizationEndpoint verifies that rawAuthzURL is a safe HTTP/HTTPS
// endpoint with no userinfo, fragment, control characters, pre-populated OAuth
// redirect parameters, or cleartext HTTP downgrade from an HTTPS API server.
func validateAuthorizationEndpoint(rawAuthzURL, apiServerURL string) (string, error) {
	trimmed := strings.TrimSpace(rawAuthzURL)
	if trimmed == "" {
		return "", fmt.Errorf("oauth discovery: metadata missing authorization_endpoint")
	}
	safeDisplay := redactEndpointForError(trimmed)
	if hasControlOrSpaceRune(trimmed) {
		return "", fmt.Errorf("oauth discovery: invalid authorization_endpoint %q: contains whitespace or control characters", safeDisplay)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("oauth discovery: invalid authorization_endpoint %q", safeDisplay)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("oauth discovery: unsupported authorization_endpoint scheme %q", sanitizeUntrustedText(u.Scheme, 32))
	}
	if u.Opaque != "" || u.User != nil || u.Hostname() == "" {
		return "", fmt.Errorf("oauth discovery: invalid authorization_endpoint %q", safeDisplay)
	}
	if u.Fragment != "" || strings.Contains(trimmed, "#") {
		return "", fmt.Errorf("oauth discovery: authorization_endpoint %q must not contain a URL fragment", safeDisplay)
	}
	if scheme == "http" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(apiServerURL)), "https://") && !isLoopbackHost(u.Hostname()) {
		return "", fmt.Errorf("oauth discovery: refusing cleartext http authorization_endpoint %q for https API server", safeDisplay)
	}
	q := u.Query()
	for _, reserved := range reservedAuthorizeQueryKeys {
		if q.Has(reserved) {
			return "", fmt.Errorf("oauth discovery: authorization_endpoint %q must not pre-populate %q", safeDisplay, reserved)
		}
	}
	return u.String(), nil
}

// discoverOAuthMetadata fetches and validates the cluster's OAuth metadata.
func discoverOAuthMetadata(ctx context.Context, client httpDoer, apiServerURL string) (*oauthMetadata, error) {
	if apiServerURL == "" {
		return nil, fmt.Errorf("api server URL is required for OAuth discovery")
	}
	endpoint := joinURL(apiServerURL, wellKnownPath)

	status, body, err := getJSON(ctx, client, endpoint, "")
	if err != nil {
		return nil, fmt.Errorf("oauth discovery request: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("oauth discovery: unexpected status %d from %s", status, redactEndpointForError(endpoint))
	}

	var meta oauthMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("oauth discovery: decode metadata: %w", err)
	}
	validAuthz, err := validateAuthorizationEndpoint(meta.AuthorizationEndpoint, apiServerURL)
	if err != nil {
		return nil, err
	}
	meta.AuthorizationEndpoint = validAuthz
	meta.Issuer = sanitizeUntrustedText(meta.Issuer, 512)
	return &meta, nil
}
