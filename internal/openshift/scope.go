// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import "strings"

// saScope identifies a service account for which to mint a scoped token.
type saScope struct {
	Namespace      string
	ServiceAccount string
	Audience       string
}

// parseSAScope interprets a token-request scope string as a service-account
// reference. It returns ok=false for an empty scope or any scope that does not
// look like a service-account reference, in which case the caller returns the
// held user token instead.
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
