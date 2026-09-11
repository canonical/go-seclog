// go-seclog
// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: LGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License version 3, as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranties of
// MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.

package seclog

import "strings"

// Sanitizer transforms any user-controlled input into an escaped string.
//
// It is used by the logger for the members of the Principal, and by the event
// constructors for the values they receive from the application. It must be
// safe for concurrent use, as one sanitizer serves every goroutine logging
// with the same logger.
type Sanitizer interface {
	Sanitize(string) string
}

// unsafeChars contains OWASP and principal delimiters.
const unsafeChars = ",<>:"

// defaultMaxLen is the length limit used when the requested one is not
// positive, so that a sanitizer is never built with a limit that would discard
// every value.
const defaultMaxLen = 64

type defaultSanitizer struct {
	// MaxLen is exported although the type is not, so that a value
	// reaching a test through EventContext.Sanitizer can still be compared
	// with reflect.DeepEqual or go-cmp, which reject unexported fields.
	MaxLen int
}

var _ Sanitizer = defaultSanitizer{}

// NewDefaultSanitizer creates a sanitizer that drops non-printable and
// non-ASCII bytes, drops OWASP delimiters, and truncates the result to
// maxLen bytes. Set 0 or below to use the default maximum length.
//
//	logger := seclog.NewLogger("my-app",
//		seclog.WithSanitizer(seclog.NewDefaultSanitizer(64)),
//	)
func NewDefaultSanitizer(maxLen int) Sanitizer {
	if maxLen < 1 {
		maxLen = defaultMaxLen
	}
	return defaultSanitizer{MaxLen: maxLen}
}

// Sanitize implements Sanitizer.
func (d defaultSanitizer) Sanitize(s string) string {
	// Go through the string until we find an invalid byte.
	keep := 0
	for keep < len(s) && keep < d.MaxLen && safeByte(s[keep]) {
		keep++
	}
	// String is valid as is.
	if keep == len(s) {
		return s
	}

	// Grow from existing start until maxLen.
	var b strings.Builder
	b.Grow(min(len(s), d.MaxLen))
	b.WriteString(s[:keep])
	for i := keep; i < len(s) && b.Len() < d.MaxLen; i++ {
		if safeByte(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// safeByte skips non-ASCII and unsafe chars.
func safeByte(b byte) bool {
	return b >= ' ' && b <= '~' && strings.IndexByte(unsafeChars, b) < 0
}
