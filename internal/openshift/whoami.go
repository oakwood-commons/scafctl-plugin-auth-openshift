// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
)

// whoamiPath returns the authenticated user for the bearer token. It is the
// OpenShift user API "self" lookup.
const whoamiPath = "/apis/user.openshift.io/v1/users/~"

// userInfo is the subset of the OpenShift User object the handler reads.
type userInfo struct {
	Metadata struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"metadata"`
	FullName string `json:"fullName"`
}

// whoami resolves the username for the given bearer token. It is best-effort:
// callers use it to enrich claims but must not block login on failure.
func whoami(ctx context.Context, client httpDoer, apiServerURL, bearer string) (*userInfo, error) {
	if apiServerURL == "" {
		return nil, fmt.Errorf("api server URL is required for whoami")
	}
	endpoint := joinURL(apiServerURL, whoamiPath)

	status, body, err := getJSON(ctx, client, endpoint, bearer)
	if err != nil {
		return nil, fmt.Errorf("whoami request: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("whoami: unexpected status %d from %s", status, endpoint)
	}

	var info userInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("whoami: decode response: %w", err)
	}
	if info.Metadata.Name == "" {
		return nil, fmt.Errorf("whoami: response missing user name")
	}
	return &info, nil
}

// resolveUsername returns the best available username for the token, logging
// and swallowing errors so enrichment never blocks authentication.
func resolveUsername(ctx context.Context, client httpDoer, apiServerURL, bearer string) string {
	lgr := logr.FromContextOrDiscard(ctx)
	info, err := whoami(ctx, client, apiServerURL, bearer)
	if err != nil {
		lgr.V(1).Info("whoami enrichment failed (non-fatal)", "error", err.Error())
		return ""
	}
	return info.Metadata.Name
}
