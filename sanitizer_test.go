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

package seclog_test

import (
	"strings"
	"testing"

	"github.com/canonical/go-seclog"
	qt "github.com/frankban/quicktest"
)

func TestDefaultSanitizer(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name   string
		maxLen int
		input  string
		want   string
	}{{
		name:   "an empty value stays empty",
		maxLen: 64,
		input:  "",
		want:   "",
	}, {
		name:   "printable ASCII is kept",
		maxLen: 64,
		input:  "user123",
		want:   "user123",
	}, {
		name:   "every printable ASCII rune is kept",
		maxLen: 64,
		input:  "user_name-1.2 (a)[b]{c}/d\\e*f?g!h#i$j%k&l'm\"n",
		want:   "user_name-1.2 (a)[b]{c}/d\\e*f?g!h#i$j%k&l'm\"n",
	}, {
		name:   "the principal delimiters are dropped",
		maxLen: 64,
		input:  "<account:admin>",
		want:   "accountadmin",
	}, {
		name:   "the qualifier separator is dropped",
		maxLen: 64,
		input:  "read,write",
		want:   "readwrite",
	}, {
		name:   "an injected principal is flattened",
		maxLen: 64,
		input:  "user1>,<account:admin",
		want:   "user1accountadmin",
	}, {
		name:   "control characters are dropped",
		maxLen: 64,
		input:  "user\n1\t2\r3",
		want:   "user123",
	}, {
		name:   "an injected record is flattened",
		maxLen: 64,
		input:  "user1\n{\"event\":\"authn_login_success\"}",
		want:   "user1{\"event\"\"authn_login_success\"}",
	}, {
		name:   "the delete character is dropped",
		maxLen: 64,
		input:  "user\x7f1",
		want:   "user1",
	}, {
		name:   "non-ASCII runes are dropped",
		maxLen: 64,
		input:  "usu\u00e1rio-jo\u00e3o",
		want:   "usurio-joo",
	}, {
		name:   "a fully non-ASCII value becomes empty",
		maxLen: 64,
		input:  "\u4f60\u597d\u4e16\u754c",
		want:   "",
	}, {
		name:   "a value of exactly the limit is kept",
		maxLen: 7,
		input:  "user123",
		want:   "user123",
	}, {
		name:   "a longer value is truncated",
		maxLen: 4,
		input:  "user123",
		want:   "user",
	}, {
		name:   "the limit applies after the dropped runes",
		maxLen: 4,
		input:  "<u><s><e><r>123",
		want:   "user",
	}, {
		name:   "a limit of zero becomes the default",
		maxLen: 0,
		input:  strings.Repeat("a", 100),
		want:   strings.Repeat("a", 64),
	}, {
		name:   "a negative limit becomes the default",
		maxLen: -1,
		input:  strings.Repeat("a", 100),
		want:   strings.Repeat("a", 64),
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			sanitizer := seclog.NewDefaultSanitizer(test.maxLen)

			c.Assert(sanitizer.Sanitize(test.input), qt.Equals, test.want)
		})
	}
}

// TestDefaultSanitizerIsIdempotent asserts that sanitizing an already
// sanitized value changes nothing, so that a value passing through two layers
// is not degraded twice.
func TestDefaultSanitizerIsIdempotent(t *testing.T) {
	c := qt.New(t)

	sanitizer := seclog.NewDefaultSanitizer(16)
	once := sanitizer.Sanitize("<account:admin>,\nuser\u00e91234567890")

	c.Assert(sanitizer.Sanitize(once), qt.Equals, once)
}

// TestDefaultSanitizerIsComparable asserts that a value carrying the default
// sanitizer stays comparable by reflection.
//
// The tests of this package, and of the packages using it, compare an
// EventContext with go-cmp, which rejects any unexported field it finds. A
// sanitizer holding one would turn those comparisons into errors instead of
// results.
func TestDefaultSanitizerIsComparable(t *testing.T) {
	c := qt.New(t)

	sanitizer := seclog.NewDefaultSanitizer(64)

	c.Assert(sanitizer, qt.Equals, seclog.NewDefaultSanitizer(64))
	c.Assert(
		seclog.EventContext{Sanitizer: sanitizer},
		qt.DeepEquals,
		seclog.EventContext{Sanitizer: seclog.NewDefaultSanitizer(64)},
	)
}
