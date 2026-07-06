// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Default configuration values for the openshift handler.
const (
	// DefaultOAuthClientID is OpenShift's public CLI OAuth client. It is a
	// configurable default; clusters may register a different public client.
	DefaultOAuthClientID = "openshift-cli-client"

	// DefaultCallbackHost is the loopback host the browser redirects to after
	// authentication. It must be a loopback address for the implicit grant to
	// be considered safe.
	DefaultCallbackHost = "127.0.0.1"

	// DefaultLoginTimeout bounds how long Login waits for the browser callback.
	DefaultLoginTimeout = 5 * time.Minute

	// DefaultHTTPTimeout bounds individual HTTP requests (discovery, whoami,
	// token minting).
	DefaultHTTPTimeout = 30 * time.Second

	// tokenExpiryLeeway is subtracted from a token's expiry when deciding
	// whether it is still usable, to avoid handing out tokens that expire
	// mid-request.
	tokenExpiryLeeway = 60 * time.Second
)

// Config holds handler-specific configuration. Everything cluster- or
// org-specific is config-driven so the handler stays generic.
type Config struct {
	// APIServerURL is the OpenShift/Kubernetes API server base URL
	// (e.g. https://api.mycluster.example.com:6443). Required for login.
	APIServerURL string `json:"apiServerUrl,omitempty" yaml:"apiServerUrl,omitempty"`

	// OAuthClientID is the public OAuth client used for the browser flow.
	// Defaults to DefaultOAuthClientID.
	OAuthClientID string `json:"oauthClientId,omitempty" yaml:"oauthClientId,omitempty"`

	// CallbackHost is the loopback host for the OAuth redirect.
	// Defaults to DefaultCallbackHost.
	CallbackHost string `json:"callbackHost,omitempty" yaml:"callbackHost,omitempty"`

	// CallbackPort is the loopback port for the OAuth redirect. Zero selects a
	// random free port (recommended).
	CallbackPort int `json:"callbackPort,omitempty" yaml:"callbackPort,omitempty"`

	// LoginTimeout bounds how long Login waits for the browser callback.
	// Defaults to DefaultLoginTimeout.
	LoginTimeout time.Duration `json:"loginTimeout,omitempty" yaml:"loginTimeout,omitempty"`

	// InsecureSkipTLSVerify disables API server certificate verification.
	// Intended for development clusters with self-signed certs only.
	InsecureSkipTLSVerify bool `json:"insecureSkipTlsVerify,omitempty" yaml:"insecureSkipTlsVerify,omitempty"`

	// Clusters maps a short alias to a cluster definition, letting callers
	// select a cluster per login via --hostname instead of a full URL.
	Clusters map[string]Cluster `json:"clusters,omitempty" yaml:"clusters,omitempty"`
}

// Cluster is a named cluster definition selectable via the login hostname.
type Cluster struct {
	// URL is the OpenShift/Kubernetes API server base URL for the cluster.
	URL string `json:"url" yaml:"url"`

	// OAuthClientID optionally overrides the public OAuth client for this
	// cluster. Empty leaves the handler default in place.
	OAuthClientID string `json:"oauthClientId,omitempty" yaml:"oauthClientId,omitempty"`
}

// DefaultConfig returns a Config populated with default values.
func DefaultConfig() *Config {
	return &Config{
		OAuthClientID: DefaultOAuthClientID,
		CallbackHost:  DefaultCallbackHost,
		CallbackPort:  0,
		LoginTimeout:  DefaultLoginTimeout,
	}
}

// applySettings overlays handler settings (from the host ProviderConfig) onto
// the config, leaving defaults in place for any unset field.
func (c *Config) applySettings(settings map[string]json.RawMessage) error {
	if len(settings) == 0 {
		return nil
	}
	// Marshal the raw settings back into a single document and decode onto a
	// shadow struct so only provided keys override defaults.
	merged := make(map[string]json.RawMessage, len(settings))
	for k, v := range settings {
		merged[k] = v
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("decode settings: %w", err)
	}
	c.normalize()
	return nil
}

// normalize fills in defaults for any field left empty.
func (c *Config) normalize() {
	c.APIServerURL = strings.TrimRight(strings.TrimSpace(c.APIServerURL), "/")
	if c.OAuthClientID == "" {
		c.OAuthClientID = DefaultOAuthClientID
	}
	if c.CallbackHost == "" {
		c.CallbackHost = DefaultCallbackHost
	}
	if c.LoginTimeout <= 0 {
		c.LoginTimeout = DefaultLoginTimeout
	}
	for alias, cluster := range c.Clusters {
		cluster.URL = strings.TrimRight(strings.TrimSpace(cluster.URL), "/")
		c.Clusters[alias] = cluster
	}
}

// resolveCluster resolves a login hostname to a concrete API server URL and an
// optional OAuth client override. Precedence: a configured alias wins, then a
// value that looks like an endpoint is treated as a direct URL/host, otherwise
// an unknown bare token is rejected.
func (c *Config) resolveCluster(hostname string) (apiServerURL, oauthClientID string, err error) {
	trimmed := strings.TrimSpace(hostname)
	if trimmed == "" {
		return "", "", fmt.Errorf("hostname is empty")
	}
	if cluster, ok := c.Clusters[trimmed]; ok {
		return strings.TrimRight(strings.TrimSpace(cluster.URL), "/"), cluster.OAuthClientID, nil
	}
	if looksLikeEndpoint(trimmed) {
		normalized, nerr := normalizeEndpoint(trimmed)
		if nerr != nil {
			return "", "", nerr
		}
		return normalized, "", nil
	}
	return "", "", fmt.Errorf("unknown cluster %q: not a known alias and not a URL/host (known aliases: %s)", trimmed, knownAliases(c.Clusters))
}

// looksLikeEndpoint reports whether a token resembles a URL or host rather than
// a bare alias label.
func looksLikeEndpoint(s string) bool {
	return strings.Contains(s, "://") || strings.Contains(s, ".") || strings.Contains(s, ":")
}

// normalizeEndpoint coerces an endpoint token into a normalized https URL,
// prepending a scheme when absent and rejecting values without a host.
func normalizeEndpoint(s string) (string, error) {
	candidate := s
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid cluster endpoint %q: %w", s, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid cluster endpoint %q: missing host", s)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// knownAliases returns a sorted, comma-separated list of configured cluster
// aliases, or "none" when empty, for use in error messages.
func knownAliases(clusters map[string]Cluster) string {
	if len(clusters) == 0 {
		return "none"
	}
	aliases := make([]string, 0, len(clusters))
	for alias := range clusters {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return strings.Join(aliases, ", ")
}
