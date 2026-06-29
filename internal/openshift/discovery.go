// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"fmt"
)

// wellKnownPath is the OAuth authorization server metadata endpoint exposed by
// the OpenShift API server (RFC 8414).
const wellKnownPath = "/.well-known/oauth-authorization-server"

// oauthMetadata is the subset of the OAuth authorization server metadata the
// handler needs. The authorization endpoint commonly lives on a different host
// than the API server (the cluster's oauth-openshift route).
type oauthMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
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
		return nil, fmt.Errorf("oauth discovery: unexpected status %d from %s", status, endpoint)
	}

	var meta oauthMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("oauth discovery: decode metadata: %w", err)
	}
	if meta.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("oauth discovery: metadata missing authorization_endpoint")
	}
	return &meta, nil
}
