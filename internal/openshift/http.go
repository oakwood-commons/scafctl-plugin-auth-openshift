// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxHTTPRedirects = 10

// httpDoer is the minimal HTTP surface the handler needs. It is satisfied by
// *http.Client and by test doubles, keeping network calls injectable.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// sameOrigin reports whether a and b share the same normalized scheme,
// canonical hostname or IP literal, and effective port (treating implicit and
// explicit HTTP/HTTPS default ports and equivalent IPv6 spellings as equal).
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || a.Scheme == "" || b.Scheme == "" {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	hostA := canonicalOriginHost(a)
	hostB := canonicalOriginHost(b)
	if hostA == "" || hostA != hostB {
		return false
	}
	portA, okA := effectiveOriginPort(a)
	portB, okB := effectiveOriginPort(b)
	return okA && okB && portA == portB
}

func canonicalOriginHost(u *url.URL) string {
	h := u.Hostname()
	if h == "" {
		return ""
	}
	if strings.HasPrefix(u.Host, "[") {
		addr, err := netip.ParseAddr(h)
		if err != nil || !addr.Is6() {
			return ""
		}
		return addr.String()
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		if !addr.Is4() {
			return ""
		}
		return addr.String()
	}
	return strings.ToLower(h)
}

func allRedirectHopsSameOrigin(via []*http.Request, target *url.URL) bool {
	if len(via) == 0 || target == nil {
		return false
	}
	origin := via[0].URL
	for i := 1; i < len(via); i++ {
		if !sameOrigin(origin, via[i].URL) {
			return false
		}
	}
	return sameOrigin(origin, target)
}

func effectiveOriginPort(u *url.URL) (string, bool) {
	rawHost := u.Host
	var p string
	switch {
	case strings.HasPrefix(rawHost, "["):
		if !strings.HasSuffix(rawHost, "]") {
			_, splitPort, err := net.SplitHostPort(rawHost)
			if err != nil || splitPort == "" || !isASCIIDigits(splitPort) {
				return "", false
			}
			p = splitPort
		}
	case strings.Contains(rawHost, ":"):
		_, splitPort, err := net.SplitHostPort(rawHost)
		if err != nil || splitPort == "" || !isASCIIDigits(splitPort) {
			return "", false
		}
		p = splitPort
	}
	if p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		return strconv.Itoa(n), true
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443", true
	case "http":
		return "80", true
	default:
		return "", false
	}
}

// newHTTPClient builds an *http.Client with the handler's timeout, TLS policy,
// and redirect guards:
//   - refuses https -> http scheme downgrades;
//   - refuses cross-origin redirects when insecureSkipTLSVerify is enabled;
//   - strips Authorization headers on any cross-origin (scheme or host:port)
//     redirect so bearer tokens never leak to different ports or subdomains.
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
		// #nosec G402 -- opt-in only, for dev clusters with self-signed certs
		InsecureSkipVerify: insecureSkipTLSVerify,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHTTPRedirects {
				return errors.New("stopped after 10 redirects")
			}
			if len(via) == 0 {
				return nil
			}
			originReq := via[0]
			if strings.EqualFold(originReq.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("refusing redirect from https to %s", sanitizeUntrustedText(req.URL.Scheme, 16))
			}
			if !allRedirectHopsSameOrigin(via, req.URL) {
				req.Header.Del("Authorization")
				if insecureSkipTLSVerify {
					return errors.New("refusing cross-origin redirect with insecureSkipTlsVerify enabled")
				}
			} else if authHdr := originReq.Header.Get("Authorization"); authHdr != "" && req.Header.Get("Authorization") == "" {
				// Go stdlib omits Authorization when equivalent IPv6 literals differ
				// textually (e.g. [::1] vs [0:0:0:0:0:0:0:1]:443); preserve it only
				// when every hop stayed on the exact same canonical origin.
				// #nosec G119 -- all redirect hops verified same scheme, canonical IP/host, and effective port
				req.Header.Set("Authorization", authHdr)
			}
			return nil
		},
	}
}

// closeHTTPClientIdle closes idle keep-alive connections on a managed
// *http.Client without disrupting any in-flight requests.
func closeHTTPClientIdle(client *http.Client) {
	if client != nil {
		client.CloseIdleConnections()
	}
}

// getJSON performs an authenticated GET and returns the response body. The
// caller is responsible for status-code handling. bearer may be empty for
// unauthenticated requests (e.g. OAuth discovery).
func getJSON(ctx context.Context, client httpDoer, reqURL, bearer string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, nil, sanitizeHTTPError(err)
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
		return 0, nil, sanitizeHTTPError(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return doRequest(client, req)
}

// doRequest executes req, redacts any URL wrappers or embedded credentials in
// transport/redirect errors, and reads the bounded response body.
func doRequest(client httpDoer, req *http.Request) (int, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, sanitizeHTTPError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Bound the body to guard against unexpectedly large responses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, sanitizeHTTPError(err)
	}
	return resp.StatusCode, body, nil
}

type sanitizedTimeoutError struct {
	msg     string
	timeout bool
}

func (e *sanitizedTimeoutError) Error() string { return e.msg }
func (e *sanitizedTimeoutError) Timeout() bool { return e.timeout }

// sanitizeHTTPError strips URL credentials, query parameters, fragments, and
// control characters from *url.Error wrappers and nested error causes before
// errors leave the HTTP boundary toward callers or logs.
func sanitizeHTTPError(err error) error {
	if err == nil {
		return nil
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return &url.Error{
			Op:  uerr.Op,
			URL: redactEndpointForError(uerr.URL),
			Err: sanitizeNestedHTTPError(uerr.Err),
		}
	}
	return sanitizeNestedHTTPError(err)
}

func sanitizeNestedHTTPError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return &url.Error{
			Op:  uerr.Op,
			URL: redactEndpointForError(uerr.URL),
			Err: sanitizeNestedHTTPError(uerr.Err),
		}
	}
	msg := redactURLTokensInText(err.Error())
	var te interface{ Timeout() bool }
	if errors.As(err, &te) {
		return &sanitizedTimeoutError{msg: msg, timeout: te.Timeout()}
	}
	return errors.New(msg)
}

func redactURLTokensInText(raw string) string {
	return sanitizeUntrustedText(redactURLTokensRaw(raw), 512)
}

func redactURLTokensRaw(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	i := 0
	for i < len(raw) {
		if raw[i] == '"' {
			end := scanQuotedEnd(raw, i+1)
			if end < 0 {
				b.WriteByte('"')
				i++
				continue
			}
			lit := raw[i : end+1]
			unquoted, err := strconv.Unquote(lit)
			if err != nil {
				unquoted = raw[i+1 : end]
			}
			b.WriteByte('"')
			switch {
			case isSingleURLSpan(unquoted):
				b.WriteString(redactEndpointForError(unquoted))
			case strings.ContainsAny(unquoted, " \t\r\n\""):
				b.WriteString(redactURLTokensRaw(unquoted))
			default:
				b.WriteString(unquoted)
			}
			b.WriteByte('"')
			i = end + 1
			continue
		}
		if raw[i] <= ' ' {
			b.WriteByte(raw[i])
			i++
			continue
		}
		j := i
		for j < len(raw) && raw[j] > ' ' && raw[j] != '"' {
			j++
		}
		tok := raw[i:j]
		if looksLikeSecretBearingURLToken(tok) {
			b.WriteString(redactEndpointForError(tok))
		} else {
			b.WriteString(tok)
		}
		i = j
	}
	return b.String()
}

func isSingleURLSpan(s string) bool {
	if s == "" {
		return false
	}
	spaceIdx := strings.IndexAny(s, " \t\r\n\"")
	if spaceIdx < 0 {
		return looksLikeSecretBearingURLToken(s)
	}
	_, _, hasScheme := splitLeadingScheme(s)
	if !hasScheme && !strings.HasPrefix(s, "/") {
		return false
	}
	if (hasScheme || strings.HasPrefix(s, "//")) && strings.IndexByte(s, '@') > spaceIdx {
		return true
	}
	qfIdx := strings.IndexAny(s, "?#")
	return qfIdx >= 0 && qfIdx < spaceIdx
}

func scanQuotedEnd(s string, start int) int {
	for i := start; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '"' {
			return i
		}
	}
	return -1
}

func looksLikeSecretBearingURLToken(tok string) bool {
	if strings.Contains(tok, "://") || strings.HasPrefix(tok, "/") || strings.ContainsAny(tok, "?#") {
		return true
	}
	return strings.Contains(tok, "@") && (strings.Contains(tok, ":") || strings.Contains(tok, "/"))
}

// joinURL joins a base URL with a path, collapsing duplicate slashes at the
// boundary.
func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

// queryEscape is a thin alias kept for readability at call sites that build
// OAuth authorize URLs.
func queryEscape(s string) string { return url.QueryEscape(s) }
