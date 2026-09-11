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
	"context"
	"testing"

	"github.com/canonical/go-seclog"
	qt "github.com/frankban/quicktest"
)

func TestPrincipalString(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      string
	}{{
		name:      "nil principal",
		principal: nil,
		want:      "unknown",
	}, {
		name:      "empty principal",
		principal: &seclog.Principal{},
		want:      "unknown",
	}, {
		name:      "using account",
		principal: &seclog.Principal{Account: "username1"},
		want:      "<account:username1>",
	}, {
		name:      "using service account",
		principal: &seclog.Principal{ServiceAccount: "service1"},
		want:      "<service_account:service1>",
	}, {
		name:      "using email",
		principal: &seclog.Principal{Email: "user@example.com"},
		want:      "<email:user@example.com>",
	}, {
		name:      "using name",
		principal: &seclog.Principal{Name: "John Doe"},
		want:      "<name:John Doe>",
	}, {
		name:      "using more than one field",
		principal: &seclog.Principal{Account: "username1", ServiceAccount: "service1"},
		want:      "<account:username1,service_account:service1>",
	}, {
		name: "name is rendered last",
		principal: &seclog.Principal{
			Account:        "username1",
			ServiceAccount: "service1",
			Email:          "user@example.com",
			Name:           "John Doe",
		},
		want: "<account:username1,service_account:service1,email:user@example.com,name:John Doe>",
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(test.principal.String(), qt.Equals, test.want)
		})
	}
}

func TestPrincipalSanitized(t *testing.T) {
	c := qt.New(t)

	sanitizer := seclog.NewDefaultSanitizer(64)

	tests := []struct {
		name       string
		principal  *seclog.Principal
		sanitizer  seclog.Sanitizer
		want       *seclog.Principal
		wantString string
	}{{
		name:       "a nil principal is kept",
		principal:  nil,
		sanitizer:  sanitizer,
		want:       nil,
		wantString: "unknown",
	}, {
		name:       "an empty principal is kept",
		principal:  &seclog.Principal{},
		sanitizer:  sanitizer,
		want:       &seclog.Principal{},
		wantString: "unknown",
	}, {
		name:       "a nil sanitizer keeps the members",
		principal:  &seclog.Principal{Account: "<admin>"},
		sanitizer:  nil,
		want:       &seclog.Principal{Account: "<admin>"},
		wantString: "<account:<admin>>",
	}, {
		name:       "a safe principal is unchanged",
		principal:  &seclog.Principal{Account: "username1"},
		sanitizer:  sanitizer,
		want:       &seclog.Principal{Account: "username1"},
		wantString: "<account:username1>",
	}, {
		name:       "every member is sanitized",
		principal:  &seclog.Principal{Account: "a,1", ServiceAccount: "s<2", Email: "e>3", Name: "n:4"},
		sanitizer:  sanitizer,
		want:       &seclog.Principal{Account: "a1", ServiceAccount: "s2", Email: "e3", Name: "n4"},
		wantString: "<account:a1,service_account:s2,email:e3,name:n4>",
	}, {
		name:       "an injected principal cannot forge a member",
		principal:  &seclog.Principal{Account: "user1>,<account:admin"},
		sanitizer:  sanitizer,
		want:       &seclog.Principal{Account: "user1accountadmin"},
		wantString: "<account:user1accountadmin>",
	}, {
		name:       "a principal left empty renders as unknown",
		principal:  &seclog.Principal{Account: ",,,"},
		sanitizer:  sanitizer,
		want:       &seclog.Principal{},
		wantString: "unknown",
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			got := test.principal.Sanitized(test.sanitizer)

			c.Assert(got, qt.DeepEquals, test.want)
			c.Assert(got.String(), qt.Equals, test.wantString)
		})
	}
}

// TestPrincipalSanitizedCopiesValue asserts that the sanitized principal is a
// copy, so that the principal stored in the context, which is shared by every
// call made with that context, is never modified.
func TestPrincipalSanitizedCopiesValue(t *testing.T) {
	c := qt.New(t)

	principal := &seclog.Principal{Account: "<admin>"}
	sanitized := principal.Sanitized(seclog.NewDefaultSanitizer(64))

	c.Assert(principal.Account, qt.Equals, "<admin>")
	c.Assert(sanitized.Account, qt.Equals, "admin")
	c.Assert(sanitized, qt.Not(qt.Equals), principal)
}

func TestContextWithPrincipal(t *testing.T) {
	c := qt.New(t)

	principal1 := &seclog.Principal{Account: "username1"}
	principal2 := &seclog.Principal{Account: "username2"}

	tests := []struct {
		name       string
		nilParent  bool
		principals []*seclog.Principal
		want       *seclog.Principal
	}{{
		name:       "without principal",
		principals: nil,
		want:       nil,
	}, {
		name:       "nil principal is ignored",
		principals: []*seclog.Principal{nil},
		want:       nil,
	}, {
		name:       "with account",
		principals: []*seclog.Principal{principal1},
		want:       principal1,
	}, {
		name:       "principal rewrite",
		principals: []*seclog.Principal{principal1, principal2},
		want:       principal2,
	}, {
		name:       "nil principal keeps the previous one",
		principals: []*seclog.Principal{principal1, nil},
		want:       principal1,
	}, {
		name:       "a nil parent is treated as background",
		nilParent:  true,
		principals: []*seclog.Principal{principal1},
		want:       principal1,
	}, {
		name:       "a nil parent with a nil principal is treated as background",
		nilParent:  true,
		principals: []*seclog.Principal{nil},
		want:       nil,
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			ctx := context.Background()
			if test.nilParent {
				ctx = nil
			}
			for _, principal := range test.principals {
				ctx = seclog.ContextWithPrincipal(ctx, principal)
			}

			// The helper never returns a nil context, so a caller that
			// builds its values before logging cannot be handed one.
			c.Assert(ctx, qt.IsNotNil)
			c.Assert(seclog.PrincipalFromContext(ctx), qt.DeepEquals, test.want)
		})
	}
}

func TestContextWithPrincipalCopiesValue(t *testing.T) {
	c := qt.New(t)

	principal := &seclog.Principal{Account: "username1"}
	ctx := seclog.ContextWithPrincipal(context.Background(), principal)
	principal.Account = "mutated"

	c.Assert(seclog.PrincipalFromContext(ctx).Account, qt.Equals, "username1")
}
