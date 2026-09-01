// Copyright 2026 Canonical Ltd.

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

func TestContextWithPrincipal(t *testing.T) {
	c := qt.New(t)

	principal1 := &seclog.Principal{Account: "username1"}
	principal2 := &seclog.Principal{Account: "username2"}

	tests := []struct {
		name       string
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
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			ctx := context.Background()
			for _, principal := range test.principals {
				ctx = seclog.ContextWithPrincipal(ctx, principal)
			}

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
