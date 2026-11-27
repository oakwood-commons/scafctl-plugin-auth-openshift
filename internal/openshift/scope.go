// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"fmt"
	"strings"
)

// saScope identifies a service account for which to mint a scoped token.
type saScope struct {
	Namespace      string
	ServiceAccount string
	Audience       string
}

// classifyTokenScope interprets a GetToken request scope:
//   - empty, "user", or "user:full" selects the held user OAuth token
//     (isSA = false, err = nil);
//   - a valid service-account scope ("<ns>/<sa>[@<aud>]" or
//     "system:serviceaccount:<ns>:<sa>[@<aud>]") returns (sa, true, nil);
//   - any other non-empty value fails closed with an error so a malformed SA
//     scope (such as "ns/" from an unset shell variable) never silently hands
//     out the user's full cluster OAuth credential.
func classifyTokenScope(scope string) (saScope, bool, error) {
	s := strings.TrimSpace(scope)
	if scope == "" || s == "user" || s == "user:full" {
		return saScope{}, false, nil
	}
	if hasControlOrSpaceRune(s) {
		return saScope{}, false, fmt.Errorf(
			"invalid token scope %q: whitespace and control characters are not allowed; use \"user\" or \"<namespace>/<serviceaccount>[@<audience>]\"",
			sanitizeUntrustedText(scope, 128),
		)
	}
	if strings.HasSuffix(s, "@") {
		return saScope{}, false, fmt.Errorf(
			"invalid token scope %q: empty audience after '@'",
			sanitizeUntrustedText(scope, 128),
		)
	}
	sa, ok := parseSAScope(s)
	if !ok {
		return saScope{}, false, fmt.Errorf(
			"unsupported token scope %q: expected \"user\" or \"<namespace>/<serviceaccount>[@<audience>]\" (or \"system:serviceaccount:<namespace>:<serviceaccount>[@<audience>]\")",
			sanitizeUntrustedText(scope, 128),
		)
	}
	return sa, true, nil
}

// parseSAScope interprets a token-request scope string as a service-account
// reference. It returns ok=false for an empty scope or any scope that does not
// match a valid service-account reference.
//
// Accepted forms:
//
//	<namespace>/<serviceaccount>
//	<namespace>/<serviceaccount>@<audience>
//	system:serviceaccount:<namespace>:<serviceaccount>
//	system:serviceaccount:<namespace>:<serviceaccount>@<audience>
func parseSAScope(scope string) (saScope, bool) {
	s := strings.TrimSpace(scope)
	if s == "" {
		return saScope{}, false
	}

	// Split off an optional @audience suffix.
	audience := ""
	if at := strings.LastIndex(s, "@"); at >= 0 {
		audience = strings.TrimSpace(s[at+1:])
		s = strings.TrimSpace(s[:at])
	}

	// Kubernetes canonical form: system:serviceaccount:<ns>:<sa>
	if rest, ok := strings.CutPrefix(s, "system:serviceaccount:"); ok {
		parts := strings.Split(rest, ":")
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return saScope{Namespace: parts[0], ServiceAccount: parts[1], Audience: audience}, true
		}
		return saScope{}, false
	}

	// Shorthand form: <ns>/<sa>
	if ns, sa, ok := strings.Cut(s, "/"); ok {
		ns = strings.TrimSpace(ns)
		sa = strings.TrimSpace(sa)
		if ns != "" && sa != "" && !strings.Contains(sa, "/") {
			return saScope{Namespace: ns, ServiceAccount: sa, Audience: audience}, true
		}
	}

	return saScope{}, false
}
