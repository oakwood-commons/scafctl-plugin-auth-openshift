// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package openshift

import (
	"strings"
	"unicode/utf8"
)

// isDisallowedControlRune reports whether r is a C0 (< 0x20), DEL (0x7f),
// C1 (U+0080..U+009F), or Unicode bidirectional formatting control character
// that must never reach terminal output, logs, or claims.
func isDisallowedControlRune(r rune) bool {
	if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) ||
		(r >= 0x2066 && r <= 0x2069)
}

// hasControlOrSpaceRune reports whether s contains invalid UTF-8, whitespace,
// or disallowed control/BiDi characters.
func hasControlOrSpaceRune(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || isDisallowedControlRune(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

// sanitizeUntrustedText removes invalid UTF-8 bytes, C0/DEL/C1 control
// characters, and Unicode BiDi overrides from untrusted remote strings,
// collapses whitespace runs to single spaces, and caps the output at maxRunes
// runes so multi-byte UTF-8 sequences are never split mid-rune.
func sanitizeUntrustedText(s string, maxRunes int) string {
	if s == "" || maxRunes <= 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(min(len(s), maxRunes*utf8.UTFMax))
	count := 0
	pendingSpace := false
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		i += width
		if r == utf8.RuneError && width == 1 {
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029' {
			if count > 0 {
				pendingSpace = true
			}
			continue
		}
		if isDisallowedControlRune(r) {
			continue
		}
		if pendingSpace {
			if count+1 >= maxRunes {
				break
			}
			b.WriteByte(' ')
			count++
			pendingSpace = false
		}
		b.WriteRune(r)
		count++
		if count >= maxRunes {
			break
		}
	}
	return b.String()
}
