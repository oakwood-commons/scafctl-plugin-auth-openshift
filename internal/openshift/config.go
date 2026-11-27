// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	oauth "github.com/oakwood-commons/oauth-helpers"
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

	// defaultWhoamiTimeout bounds the best-effort post-callback whoami lookup so
	// an unresponsive user API never delays credential persistence for 30s.
	defaultWhoamiTimeout = 5 * time.Second

	// defaultAssumedTokenTTL is anchored to capture/cache time when an OAuth
	// server omits expires_in in the implicit-grant fragment (matching
	// OpenShift's default 24h accessTokenMaxAgeSeconds) so token usability and
	// gRPC responses use a fixed lifetime rather than sliding forward per call.
	defaultAssumedTokenTTL = 24 * time.Hour

	// tokenExpiryLeeway is subtracted from a token's expiry when deciding
	// whether it is still usable, to avoid handing out tokens that expire
	// mid-request.
	tokenExpiryLeeway = 60 * time.Second
)

// disallowedBareSchemePrefixes lists URI schemes that must be rejected when
// supplied without "://" (e.g. "http:/api.example.com" or "javascript:80").
var disallowedBareSchemePrefixes = map[string]bool{
	"http":       true,
	"https":      true,
	"ftp":        true,
	"file":       true,
	"javascript": true,
	"data":       true,
	"mailto":     true,
	"ws":         true,
	"wss":        true,
}

// Config holds handler-specific configuration. Everything cluster- or
// org-specific is config-driven so the handler stays generic.
type Config struct {
	// APIServerURL is the OpenShift/Kubernetes API server base URL
	// (e.g. https://api.mycluster.example.com:6443). Required for login when
	// no --hostname or environment variable is supplied.
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
	// select a cluster per login/token/status/logout via --hostname instead of
	// a full URL.
	Clusters map[string]Cluster `json:"clusters,omitempty" yaml:"clusters,omitempty"`

	// hasClientIDOverride records whether OAuthClientID came from the CLI
	// runtime override key ("clientId"), which takes precedence over both
	// handler-level oauthClientId and per-cluster alias oauthClientId.
	hasClientIDOverride bool
}

// Cluster is a named cluster definition selectable via the hostname parameter.
type Cluster struct {
	// URL is the OpenShift/Kubernetes API server base URL for the cluster.
	URL string `json:"url" yaml:"url"`

	// OAuthClientID optionally overrides the public OAuth client for this
	// cluster. Empty leaves the handler default in place.
	OAuthClientID string `json:"oauthClientId,omitempty" yaml:"oauthClientId,omitempty"`
}

// durationOrString decodes either a JSON string duration (e.g. "2m") or a JSON
// integer nanosecond duration (encoding/json's native time.Duration format).
type durationOrString time.Duration

func (d *durationOrString) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		if strings.TrimSpace(s) == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", sanitizeUntrustedText(s, 64), err)
		}
		*d = durationOrString(parsed)
		return nil
	}
	var ns int64
	if err := json.Unmarshal(trimmed, &ns); err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = durationOrString(time.Duration(ns))
	return nil
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

// clone returns a deep copy of c so per-RPC normalization and overrides never
// mutate shared plugin configuration.
func (c *Config) clone() *Config {
	if c == nil {
		return DefaultConfig()
	}
	cp := *c
	if c.Clusters != nil {
		clusters := make(map[string]Cluster, len(c.Clusters))
		for k, v := range c.Clusters {
			clusters[k] = v
		}
		cp.Clusters = clusters
	}
	return &cp
}

// normalizeCallbackHost canonicalizes a loopback host token (trimming
// whitespace, lowercasing "localhost", and unwrapping IPv6 brackets "[::1]" ->
// "::1").
func normalizeCallbackHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return h
}

// applySettings overlays handler settings (from ProviderConfig.Settings or
// per-RPC RequestSettings) onto the config, leaving defaults in place for any
// unset field. It accepts both the host-enveloped shape
// (settings["openshift"] = {...}) and flat top-level setting keys, as well as
// the host's ApplyOverrides "clientId" key.
func (c *Config) applySettings(settings map[string]json.RawMessage) error {
	if len(settings) == 0 {
		return nil
	}

	var data []byte
	var outerClientID *string
	if nested, hasHandler := settings[HandlerName]; hasHandler {
		for k, rawCID := range settings {
			if strings.EqualFold(k, "clientId") {
				var topCID string
				if err := json.Unmarshal(rawCID, &topCID); err == nil {
					outerClientID = &topCID
				}
				break
			}
		}
		trimmed := bytes.TrimSpace(nested)
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			if outerClientID != nil && strings.TrimSpace(*outerClientID) != "" {
				c.OAuthClientID = strings.TrimSpace(*outerClientID)
				c.hasClientIDOverride = true
			}
			c.normalize()
			return nil
		}
		data = trimmed
	} else {
		merged := make(map[string]json.RawMessage, len(settings))
		for k, v := range settings {
			merged[k] = v
		}
		var err error
		data, err = json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("marshal settings: %w", err)
		}
	}

	type rawFields struct {
		APIServerURL          *string            `json:"apiServerUrl"`
		OAuthClientID         *string            `json:"oauthClientId"`
		ClientID              *string            `json:"clientId"`
		CallbackHost          *string            `json:"callbackHost"`
		CallbackPort          *int               `json:"callbackPort"`
		LoginTimeout          *durationOrString  `json:"loginTimeout"`
		InsecureSkipTLSVerify *bool              `json:"insecureSkipTlsVerify"`
		Clusters              map[string]Cluster `json:"clusters"`
		NestedSettings        json.RawMessage    `json:"settings"`
	}
	var decoded rawFields
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("decode settings: %w", err)
	}

	// If a caller nested keys under an extra "settings:" block, decode that
	// inner block and let any explicit outer fields (such as a merged runtime
	// "clientId" override) take precedence without dropping inner settings.
	if trimmedNested := bytes.TrimSpace(decoded.NestedSettings); len(trimmedNested) > 0 && !bytes.Equal(trimmedNested, []byte("null")) {
		var inner rawFields
		if err := json.Unmarshal(trimmedNested, &inner); err != nil {
			return fmt.Errorf("decode nested settings: %w", err)
		}
		if decoded.APIServerURL == nil {
			decoded.APIServerURL = inner.APIServerURL
		}
		if decoded.OAuthClientID == nil {
			decoded.OAuthClientID = inner.OAuthClientID
		}
		if decoded.ClientID == nil {
			decoded.ClientID = inner.ClientID
		}
		if decoded.CallbackHost == nil {
			decoded.CallbackHost = inner.CallbackHost
		}
		if decoded.CallbackPort == nil {
			decoded.CallbackPort = inner.CallbackPort
		}
		if decoded.LoginTimeout == nil {
			decoded.LoginTimeout = inner.LoginTimeout
		}
		if decoded.InsecureSkipTLSVerify == nil {
			decoded.InsecureSkipTLSVerify = inner.InsecureSkipTLSVerify
		}
		if decoded.Clusters == nil {
			decoded.Clusters = inner.Clusters
		}
	}

	if decoded.APIServerURL != nil {
		c.APIServerURL = *decoded.APIServerURL
	}
	overrideCID := decoded.ClientID
	if overrideCID == nil {
		overrideCID = outerClientID
	}
	if overrideCID != nil && strings.TrimSpace(*overrideCID) != "" {
		c.OAuthClientID = strings.TrimSpace(*overrideCID)
		c.hasClientIDOverride = true
	} else if decoded.OAuthClientID != nil {
		c.OAuthClientID = *decoded.OAuthClientID
		c.hasClientIDOverride = false
	} else if overrideCID != nil {
		c.OAuthClientID = ""
		c.hasClientIDOverride = false
	}
	if decoded.CallbackHost != nil {
		normHost := normalizeCallbackHost(*decoded.CallbackHost)
		if normHost != "" {
			if err := oauth.ValidateCallbackHostPath(normHost, callbackPath); err != nil {
				return fmt.Errorf("invalid loopback callbackHost %q: %w", sanitizeUntrustedText(*decoded.CallbackHost, 64), err)
			}
		}
		c.CallbackHost = normHost
	}
	if decoded.CallbackPort != nil {
		port := *decoded.CallbackPort
		if port != 0 && (port < 1024 || port > 65535) {
			return fmt.Errorf("invalid callbackPort %d: must be 0 or an unprivileged TCP port (1024-65535)", port)
		}
		c.CallbackPort = port
	}
	if decoded.LoginTimeout != nil {
		c.LoginTimeout = time.Duration(*decoded.LoginTimeout)
	}
	if decoded.InsecureSkipTLSVerify != nil {
		c.InsecureSkipTLSVerify = *decoded.InsecureSkipTLSVerify
	}
	if decoded.Clusters != nil {
		c.Clusters = decoded.Clusters
	}

	c.normalize()
	return nil
}

// normalize fills in defaults for any field left empty and canonicalizes valid
// cluster URLs so config-sourced and hostname-sourced URLs derive identical
// cache keys.
func (c *Config) normalize() {
	c.APIServerURL = canonicalizeOrTrimURL(c.APIServerURL)
	if c.OAuthClientID == "" {
		c.OAuthClientID = DefaultOAuthClientID
	}
	c.CallbackHost = normalizeCallbackHost(c.CallbackHost)
	if c.CallbackHost == "" {
		c.CallbackHost = DefaultCallbackHost
	}
	if c.LoginTimeout <= 0 {
		c.LoginTimeout = DefaultLoginTimeout
	}
	for alias, cluster := range c.Clusters {
		cluster.URL = canonicalizeOrTrimURL(cluster.URL)
		c.Clusters[alias] = cluster
	}
}

// canonicalizeOrTrimURL returns normalizeEndpoint(raw) when raw is a valid
// endpoint, or a whitespace/slash-trimmed string when empty or malformed so
// resolution-time validation can still report a descriptive error.
func canonicalizeOrTrimURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if norm, err := normalizeEndpoint(trimmed); err == nil {
		return norm
	}
	return strings.TrimRight(trimmed, "/")
}

// lookupClusterAlias resolves trimmed against c.Clusters, checking an exact key
// match first and falling back to a deterministic case-insensitive match so
// Viper-lowercased config map keys still match mixed-case CLI --hostname values.
func (c *Config) lookupClusterAlias(trimmed string) (Cluster, bool) {
	if len(c.Clusters) == 0 {
		return Cluster{}, false
	}
	if cluster, ok := c.Clusters[trimmed]; ok {
		return cluster, true
	}
	if cluster, ok := c.Clusters[strings.ToLower(trimmed)]; ok {
		return cluster, true
	}
	keys := make([]string, 0, len(c.Clusters))
	for k := range c.Clusters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, trimmed) {
			return c.Clusters[k], true
		}
	}
	return Cluster{}, false
}

// resolveCluster resolves a hostname selector to a canonical API server URL
// and an optional OAuth client override. Precedence: a configured alias wins,
// then a value that looks like an endpoint is normalized as a direct URL/host,
// otherwise an unknown bare token is rejected.
func (c *Config) resolveCluster(hostname string) (apiServerURL, oauthClientID string, err error) {
	trimmed := strings.TrimSpace(hostname)
	if trimmed == "" {
		return "", "", fmt.Errorf("hostname is empty")
	}
	if cluster, ok := c.lookupClusterAlias(trimmed); ok {
		if strings.TrimSpace(cluster.URL) == "" {
			return "", "", fmt.Errorf("cluster alias %q has an empty url", sanitizeUntrustedText(trimmed, 128))
		}
		normalized, nerr := normalizeEndpoint(cluster.URL)
		if nerr != nil {
			return "", "", fmt.Errorf("cluster alias %q: %w", sanitizeUntrustedText(trimmed, 128), nerr)
		}
		return normalized, cluster.OAuthClientID, nil
	}
	if looksLikeEndpoint(trimmed) {
		normalized, nerr := normalizeEndpoint(trimmed)
		if nerr != nil {
			return "", "", nerr
		}
		return normalized, "", nil
	}
	return "", "", fmt.Errorf("unknown cluster %q: not a known alias and not a URL/host (known aliases: %s)", sanitizeUntrustedText(trimmed, 128), knownAliases(c.Clusters))
}

// looksLikeEndpoint reports whether a token resembles a URL or host rather than
// a bare alias label.
func looksLikeEndpoint(s string) bool {
	return strings.Contains(s, "://") || strings.Contains(s, ".") || strings.Contains(s, ":")
}

// isValidURIScheme reports whether s conforms to RFC 3986 scheme syntax
// (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )).
func isValidURIScheme(s string) bool {
	if s == "" {
		return false
	}
	c0 := s[0]
	if (c0 < 'a' || c0 > 'z') && (c0 < 'A' || c0 > 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if !isAlpha && !isDigit && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// splitLeadingScheme extracts a leading "<scheme>://" prefix only when the
// substring before "://" is a valid RFC 3986 scheme, preventing "://" inside
// userinfo, query parameters, or fragments on schemeless inputs from being
// mistaken for a URL scheme.
func splitLeadingScheme(s string) (prefix, rest string, ok bool) {
	idx := strings.Index(s, "://")
	if idx <= 0 || !isValidURIScheme(s[:idx]) {
		return "", s, false
	}
	return s[:idx+3], s[idx+3:], true
}

// isASCIIDigits reports whether s is non-empty and consists solely of ASCII
// decimal digits.
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hasAmbiguousColonSecret reports whether authority carries an unclosed '[' or
// a non-numeric suffix after ':' (such as a malformed "https://alice:Secret123"
// URL where "@host" was omitted and a password sits in the port position).
func hasAmbiguousColonSecret(authority string) bool {
	if authority == "" {
		return false
	}
	if strings.HasPrefix(authority, "[") {
		closeIdx := strings.IndexByte(authority, ']')
		if closeIdx < 0 {
			return true
		}
		rest := authority[closeIdx+1:]
		if rest == "" || rest == ":" {
			return false
		}
		if strings.HasPrefix(rest, ":") && isASCIIDigits(rest[1:]) {
			return false
		}
		return true
	}
	_, afterColon, hasColon := strings.Cut(authority, ":")
	if !hasColon || afterColon == "" {
		return false
	}
	return !isASCIIDigits(afterColon)
}

// redactEndpointForError strips userinfo credentials, query parameters, URL
// fragments, and control characters from raw before embedding it in an error
// message so accidentally pasted passwords or tokens never leak to logs,
// CLI stderr, or Status.Reason.
func redactEndpointForError(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	prefix, rest, _ := splitLeadingScheme(s)

	authority := rest
	tail := ""
	if delimIdx := strings.IndexAny(rest, "/?#"); delimIdx >= 0 {
		authority = rest[:delimIdx]
		tail = rest[delimIdx:]
	}

	// If '@' appears after '/', '?', or '#', userinfo may contain unescaped
	// delimiters (such as '?' or '/' inside the password before '@host') where
	// truncating at those delimiters would expose the password. Replace the
	// remainder with a generic redacted placeholder.
	if strings.Contains(tail, "@") {
		return sanitizeUntrustedText(prefix+"<redacted>", 128)
	}

	if atIdx := strings.LastIndexByte(authority, '@'); atIdx >= 0 {
		authority = authority[atIdx+1:]
	}

	if hasAmbiguousColonSecret(authority) {
		return sanitizeUntrustedText(prefix+"<redacted>", 128)
	}

	// Guard single-slash or triple-slash typos ("https:/alice:Secret123" or
	// "https:///alice:Secret123") where the intended authority landed in the
	// leading path segment.
	if (authority == "" || (prefix == "" && strings.HasSuffix(authority, ":"))) && strings.HasPrefix(tail, "/") {
		firstSeg := strings.TrimLeft(tail, "/")
		if nextDelim := strings.IndexAny(firstSeg, "/?#"); nextDelim >= 0 {
			firstSeg = firstSeg[:nextDelim]
		}
		if hasAmbiguousColonSecret(firstSeg) {
			return sanitizeUntrustedText(prefix+"<redacted>", 128)
		}
	}

	pathPart := tail
	if qIdx := strings.IndexAny(pathPart, "?#"); qIdx >= 0 {
		pathPart = pathPart[:qIdx]
	}
	return sanitizeUntrustedText(prefix+authority+pathPart, 128)
}

// hasDisallowedPathTraversal reports whether u contains ".." path traversal
// segments or percent-encoded path separators (%2f, %5c).
func hasDisallowedPathTraversal(u *url.URL) bool {
	escapedLower := strings.ToLower(u.EscapedPath())
	if strings.Contains(escapedLower, "%2f") || strings.Contains(escapedLower, "%5c") {
		return true
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." || seg == "." {
			return true
		}
	}
	return false
}

// normalizeEndpoint coerces an endpoint token into a canonical http/https URL:
//   - prepends "https://" when no scheme is present (after rejecting malformed
//     scheme-without-slashes prefixes such as "http:/..." or "javascript:...");
//   - lowercases scheme and DNS hostnames (stripping any trailing DNS root dot)
//     and canonicalizes IPv4/IPv6 literals via netip.ParseAddr while preserving
//     case-sensitive IPv6 zone identifiers;
//   - strips default ports (:443 for https, :80 for http) while preserving
//     explicit non-default ports such as :6443;
//   - trims trailing slashes from the path while rejecting ".." traversal and
//     encoded slashes;
//   - rejects missing hosts, unsupported schemes, user credentials, queries,
//     fragments, and control characters, redacting raw inputs in all errors.
func normalizeEndpoint(s string) (string, error) {
	safeDisplay := redactEndpointForError(s)
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", fmt.Errorf("invalid cluster endpoint %q: missing host", safeDisplay)
	}
	if hasControlOrSpaceRune(trimmed) {
		return "", fmt.Errorf("invalid cluster endpoint %q: contains whitespace or control characters", safeDisplay)
	}

	candidate := trimmed
	if _, _, hasScheme := splitLeadingScheme(candidate); !hasScheme {
		if prefix, rest, hasColon := strings.Cut(candidate, ":"); hasColon && !strings.HasPrefix(candidate, "[") {
			if disallowedBareSchemePrefixes[strings.ToLower(prefix)] || strings.HasPrefix(rest, "/") {
				return "", fmt.Errorf("invalid cluster endpoint %q: malformed scheme or port", safeDisplay)
			}
		}
		candidate = "https://" + candidate
	}

	u, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid cluster endpoint %q: invalid URL syntax", safeDisplay)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("invalid cluster endpoint %q: unsupported scheme %q (must be http or https)", safeDisplay, sanitizeUntrustedText(u.Scheme, 32))
	}
	if u.Opaque != "" {
		return "", fmt.Errorf("invalid cluster endpoint %q: opaque URL is not supported", safeDisplay)
	}
	if u.User != nil {
		return "", fmt.Errorf("invalid cluster endpoint %q: user credentials are not allowed in URL", safeDisplay)
	}
	if u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(trimmed, "?#") {
		return "", fmt.Errorf("invalid cluster endpoint %q: query and fragment are not allowed", safeDisplay)
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("invalid cluster endpoint %q: empty port", safeDisplay)
	}

	rawHost := u.Hostname()
	if rawHost == "" {
		return "", fmt.Errorf("invalid cluster endpoint %q: missing host", safeDisplay)
	}

	port := u.Port()
	if port != "" {
		portNum, perr := strconv.Atoi(port)
		if perr != nil || portNum < 1 || portNum > 65535 {
			return "", fmt.Errorf("invalid cluster endpoint %q: invalid port %q", safeDisplay, sanitizeUntrustedText(port, 16))
		}
		if (scheme == "https" && portNum == 443) || (scheme == "http" && portNum == 80) {
			port = ""
		} else {
			port = strconv.Itoa(portNum)
		}
	}

	if hasDisallowedPathTraversal(u) {
		return "", fmt.Errorf("invalid cluster endpoint %q: path traversal segments are not allowed", safeDisplay)
	}

	cleanPath := strings.TrimRight(u.Path, "/")

	if strings.HasPrefix(u.Host, "[") {
		addr, aerr := netip.ParseAddr(rawHost)
		if aerr != nil || !addr.Is6() {
			return "", fmt.Errorf("invalid cluster endpoint %q: invalid IPv6 host", safeDisplay)
		}
		bracketedHost := "[" + addr.WithZone("").String()
		if zone := addr.Zone(); zone != "" {
			bracketedHost += "%25" + encodeRFC6874Zone(zone)
		}
		bracketedHost += "]"
		if port != "" {
			bracketedHost += ":" + port
		}
		escapedPath := (&url.URL{Path: cleanPath}).EscapedPath()
		return scheme + "://" + bracketedHost + escapedPath, nil
	}

	var hostname string
	if addr, aerr := netip.ParseAddr(rawHost); aerr == nil {
		if !addr.Is4() {
			return "", fmt.Errorf("invalid cluster endpoint %q: invalid host", safeDisplay)
		}
		hostname = addr.String()
	} else {
		hostname = strings.TrimSuffix(strings.ToLower(rawHost), ".")
		if hostname == "" {
			return "", fmt.Errorf("invalid cluster endpoint %q: missing host", safeDisplay)
		}
	}

	host := hostname
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}

	return (&url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   cleanPath,
	}).String(), nil
}

// encodeRFC6874Zone percent-encodes an IPv6 zone identifier per RFC 6874,
// preserving ASCII unreserved characters (including case) while encoding '%'
// as "%25" and any other non-unreserved byte as uppercase "%XX" so url.Parse
// round-trips distinct zone names without double-decoding or case folding.
func encodeRFC6874Zone(zone string) string {
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(zone))
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0x0f])
	}
	return b.String()
}

// knownAliases returns a sorted, comma-separated list of configured cluster
// aliases, or "none" when empty, for use in error messages.
func knownAliases(clusters map[string]Cluster) string {
	if len(clusters) == 0 {
		return "none"
	}
	aliases := make([]string, 0, len(clusters))
	for alias := range clusters {
		aliases = append(aliases, sanitizeUntrustedText(alias, 64))
	}
	sort.Strings(aliases)
	return strings.Join(aliases, ", ")
}
