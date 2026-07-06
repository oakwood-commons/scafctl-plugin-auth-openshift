// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// defaultSATokenExpirationSeconds is the requested lifetime for minted
// service-account tokens when the caller does not specify one.
const defaultSATokenExpirationSeconds = 3600

// tokenRequestSpec mirrors the Kubernetes TokenRequest API request body
// (authentication.k8s.io/v1).
type tokenRequestSpec struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Audiences         []string `json:"audiences,omitempty"`
		ExpirationSeconds int      `json:"expirationSeconds,omitempty"`
	} `json:"spec"`
}

// tokenRequestResponse mirrors the relevant fields of the TokenRequest API
// response.
type tokenRequestResponse struct {
	Status struct {
		Token               string    `json:"token"`
		ExpirationTimestamp time.Time `json:"expirationTimestamp"`
	} `json:"status"`
}

// mintSAParams holds the inputs for minting a service-account token.
type mintSAParams struct {
	APIServerURL      string
	BearerToken       string // held user token used to authorize the request
	Namespace         string
	ServiceAccount    string
	Audience          string
	ExpirationSeconds int
}

// mintServiceAccountToken requests a scoped token for a service account via the
// Kubernetes TokenRequest API. No oc/kubectl binary is required.
func mintServiceAccountToken(ctx context.Context, client httpDoer, p mintSAParams) (*cacheEntry, error) {
	if p.APIServerURL == "" {
		return nil, fmt.Errorf("api server URL is required to mint a token")
	}
	if p.Namespace == "" || p.ServiceAccount == "" {
		return nil, fmt.Errorf("namespace and service account are required to mint a token")
	}
	if err := validateK8sName(p.Namespace); err != nil {
		return nil, fmt.Errorf("invalid namespace %q: %w", p.Namespace, err)
	}
	if err := validateK8sName(p.ServiceAccount); err != nil {
		return nil, fmt.Errorf("invalid service account %q: %w", p.ServiceAccount, err)
	}
	if p.BearerToken == "" {
		return nil, fmt.Errorf("not authenticated: log in before minting a service-account token")
	}

	expSecs := p.ExpirationSeconds
	if expSecs <= 0 {
		expSecs = defaultSATokenExpirationSeconds
	}

	var reqBody tokenRequestSpec
	reqBody.APIVersion = "authentication.k8s.io/v1"
	reqBody.Kind = "TokenRequest"
	if p.Audience != "" {
		reqBody.Spec.Audiences = []string{p.Audience}
	}
	reqBody.Spec.ExpirationSeconds = expSecs

	payload, err := json.Marshal(&reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal token request: %w", err)
	}

	endpoint := joinURL(p.APIServerURL, fmt.Sprintf(
		"/api/v1/namespaces/%s/serviceaccounts/%s/token",
		p.Namespace, p.ServiceAccount,
	))

	status, body, err := postJSON(ctx, client, endpoint, p.BearerToken, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	if status != 200 && status != 201 {
		return nil, fmt.Errorf("token request failed: status %d: %s", status, truncate(body, 256))
	}

	var resp tokenRequestResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if resp.Status.Token == "" {
		return nil, fmt.Errorf("token request: empty token in response")
	}

	return &cacheEntry{
		AccessToken:    resp.Status.Token,
		TokenType:      "Bearer",
		ExpiresAt:      resp.Status.ExpirationTimestamp,
		CachedAt:       time.Now(),
		Kind:           kindServiceAccount,
		APIServer:      p.APIServerURL,
		Namespace:      p.Namespace,
		ServiceAccount: p.ServiceAccount,
		Audience:       p.Audience,
	}, nil
}

// k8sNamePattern matches Kubernetes DNS-1123 subdomain names (lowercase
// alphanumeric, '-' and '.', starting and ending with an alphanumeric). It
// rejects path-breaking characters such as "/", "?", "#", whitespace and
// control characters, preventing path-segment injection when names are
// interpolated into the TokenRequest API path.
var k8sNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// validateK8sName rejects names that would break or be injected into the
// Kubernetes API request path.
func validateK8sName(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("name exceeds 253 characters")
	}
	if !k8sNamePattern.MatchString(name) {
		return fmt.Errorf("name must be a DNS-1123 subdomain (lowercase alphanumeric, '-' or '.')")
	}
	return nil
}

// truncate returns at most n bytes of b as a string, for safe error messages.
func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}
