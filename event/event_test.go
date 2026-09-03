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

package event_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/canonical/go-seclog"
	"github.com/canonical/go-seclog/event"
	qt "github.com/frankban/quicktest"
)

// principal is the actor used by every "with principal" test case.
var principal = &seclog.Principal{Account: "username1"}

// identity is the OWASP-facing part of an event: the part that must stay
// stable for existing log consumers.
type identity struct {
	Name        string
	Severity    seclog.Severity
	Qualifiers  []string
	Description string
}

// build evaluates an event function with the given principal and returns the
// OWASP identity of the resulting event.
func build(eventFunc seclog.EventFunc, actor *seclog.Principal) identity {
	e := eventFunc(seclog.EventContext{Principal: actor})
	return identity{
		Name:        e.Name,
		Severity:    e.Severity,
		Qualifiers:  e.Qualifiers,
		Description: e.Description,
	}
}

// classification is the ECS-facing part of an event.
type classification struct {
	Kind       string
	Action     string
	Categories []string
	Types      []string
	Outcome    seclog.Outcome
}

// classify evaluates an event function and returns the ECS classification of
// the resulting event.
func classify(eventFunc seclog.EventFunc) classification {
	e := eventFunc(seclog.EventContext{})
	return classification{
		Kind:       e.Kind,
		Action:     e.Action,
		Categories: e.Categories,
		Types:      e.Types,
		Outcome:    e.Outcome,
	}
}

// ecs builds the expected classification of an event, whose kind is always
// "event".
func ecs(action, category, eventType string, outcome seclog.Outcome) classification {
	return classification{
		Kind:       seclog.KindEvent,
		Action:     action,
		Categories: []string{category},
		Types:      []string{eventType},
		Outcome:    outcome,
	}
}

func TestAuthenticationLoginSuccess(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "authn_login_success",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown"},
			Description: "User unknown login successfully",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "authn_login_success",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"<account:username1>"},
			Description: "User <account:username1> login successfully",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationLoginSuccess(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationLoginFail(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "authn_login_fail",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown"},
			Description: "User unknown login failed",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "authn_login_fail",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>"},
			Description: "User <account:username1> login failed",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationLoginFail(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationLoginFailMaxTries(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name        string
		principal   *seclog.Principal
		maxAttempts int
		want        identity
	}{{
		name:        "no principal",
		principal:   nil,
		maxAttempts: 0,
		want: identity{
			Name:        "authn_login_fail_max_tries",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown", "0"},
			Description: "User unknown reached the login fail limit of 0",
		},
	}, {
		name:        "with principal",
		principal:   principal,
		maxAttempts: 3,
		want: identity{
			Name:        "authn_login_fail_max_tries",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>", "3"},
			Description: "User <account:username1> reached the login fail limit of 3",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			got := build(event.AuthenticationLoginFailMaxTries(test.maxAttempts), test.principal)
			c.Assert(got, qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationLoginLock(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		reason    event.LoginLockReason
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		reason:    event.LoginLockReasonMaxRetries,
		want: identity{
			Name:        "authn_login_lock",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown", "maxretries"},
			Description: "User unknown login locked because maxretries",
		},
	}, {
		name:      "suspicious activity",
		principal: principal,
		reason:    event.LoginLockReasonSuspicious,
		want: identity{
			Name:        "authn_login_lock",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>", "suspicious"},
			Description: "User <account:username1> login locked because suspicious",
		},
	}, {
		name:      "customer request",
		principal: principal,
		reason:    event.LoginLockReasonCustomer,
		want: identity{
			Name:        "authn_login_lock",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>", "customer"},
			Description: "User <account:username1> login locked because customer",
		},
	}, {
		name:      "other reason",
		principal: principal,
		reason:    event.LoginLockReasonOther,
		want: identity{
			Name:        "authn_login_lock",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>", "other"},
			Description: "User <account:username1> login locked because other",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationLoginLock(test.reason), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationLoginLockReason(t *testing.T) {
	c := qt.New(t)

	c.Assert(event.AuthenticationLoginLock(event.LoginLockReasonMaxRetries)(seclog.EventContext{}).Reason,
		qt.Equals, "maxretries")
}

func TestAuthenticationPasswordChange(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "authn_password_change",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown"},
			Description: "User unknown has successfully changed their password",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "authn_password_change",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"<account:username1>"},
			Description: "User <account:username1> has successfully changed their password",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationPasswordChange(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationPasswordChangeFail(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "authn_password_change_fail",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown"},
			Description: "User unknown failed to change their password",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "authn_password_change_fail",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>"},
			Description: "User <account:username1> failed to change their password",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationPasswordChangeFail(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationTokenCreated(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name         string
		principal    *seclog.Principal
		entitlements []string
		want         identity
	}{{
		name:         "no principal and no entitlements",
		principal:    nil,
		entitlements: nil,
		want: identity{
			Name:        "authn_token_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown", ""},
			Description: "A token has been created for unknown with entitlements <>",
		},
	}, {
		name:         "one entitlement",
		principal:    principal,
		entitlements: []string{"read"},
		want: identity{
			Name:        "authn_token_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"<account:username1>", "read"},
			Description: "A token has been created for <account:username1> with entitlements <read>",
		},
	}, {
		name:         "several entitlements",
		principal:    principal,
		entitlements: []string{"read", "write"},
		want: identity{
			Name:        "authn_token_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"<account:username1>", "read,write"},
			Description: "A token has been created for <account:username1> with entitlements <read,write>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			got := build(event.AuthenticationTokenCreated(test.entitlements...), test.principal)
			c.Assert(got, qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationTokenRevoked(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		tokenID   string
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		tokenID:   "token1",
		want: identity{
			Name:        "authn_token_revoked",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown", "token1"},
			Description: "Token <id:token1> was revoked for user unknown",
		},
	}, {
		name:      "with principal",
		principal: principal,
		tokenID:   "token1",
		want: identity{
			Name:        "authn_token_revoked",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"<account:username1>", "token1"},
			Description: "Token <id:token1> was revoked for user <account:username1>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationTokenRevoked(test.tokenID), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationTokenReuse(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		tokenID   string
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		tokenID:   "token1",
		want: identity{
			Name:        "authn_token_reuse",
			Severity:    seclog.SeverityCritical,
			Qualifiers:  []string{"unknown", "token1"},
			Description: "User unknown attempted to use token <id:token1>",
		},
	}, {
		name:      "with principal",
		principal: principal,
		tokenID:   "token1",
		want: identity{
			Name:        "authn_token_reuse",
			Severity:    seclog.SeverityCritical,
			Qualifiers:  []string{"<account:username1>", "token1"},
			Description: "User <account:username1> attempted to use token <id:token1>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationTokenReuse(test.tokenID), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthenticationTokenDelete(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "authn_token_delete",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown"},
			Description: "The token for user unknown has been deleted",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "authn_token_delete",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>"},
			Description: "The token for user <account:username1> has been deleted",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthenticationTokenDelete(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthorizationFail(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		resource  string
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		resource:  "database",
		want: identity{
			Name:        "authz_fail",
			Severity:    seclog.SeverityCritical,
			Qualifiers:  []string{"unknown", "database"},
			Description: "User unknown attempted to access <resource:database>",
		},
	}, {
		name:      "with principal",
		principal: principal,
		resource:  "database",
		want: identity{
			Name:        "authz_fail",
			Severity:    seclog.SeverityCritical,
			Qualifiers:  []string{"<account:username1>", "database"},
			Description: "User <account:username1> attempted to access <resource:database>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.AuthorizationFail(test.resource), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestAuthorizationAdmin(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		action    string
		details   string
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		action:    "user-delete",
		details:   "removed user1",
		want: identity{
			Name:        "authz_admin",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown", "user-delete"},
			Description: "Admin unknown performed <event:user-delete>: removed user1",
		},
	}, {
		name:      "with principal",
		principal: principal,
		action:    "user-delete",
		details:   "removed user1",
		want: identity{
			Name:        "authz_admin",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>", "user-delete"},
			Description: "Admin <account:username1> performed <event:user-delete>: removed user1",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			got := build(event.AuthorizationAdmin(test.action, test.details), test.principal)
			c.Assert(got, qt.DeepEquals, test.want)
		})
	}
}

func TestSystemStartup(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "sys_startup",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown"},
			Description: "User unknown spawned a new instance",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "sys_startup",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>"},
			Description: "User <account:username1> spawned a new instance",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.SystemStartup(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestSystemShutdown(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "sys_shutdown",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown"},
			Description: "User unknown stopped this instance",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "sys_shutdown",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>"},
			Description: "User <account:username1> stopped this instance",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.SystemShutdown(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestSystemRestart(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		want: identity{
			Name:        "sys_restart",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown"},
			Description: "User unknown initiated a restart",
		},
	}, {
		name:      "with principal",
		principal: principal,
		want: identity{
			Name:        "sys_restart",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>"},
			Description: "User <account:username1> initiated a restart",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.SystemRestart(), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestSystemCrash(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		reason    string
		want      identity
	}{{
		name:      "with a reason",
		principal: nil,
		reason:    "out-of-memory",
		want: identity{
			Name:        "sys_crash",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"out-of-memory"},
			Description: "Instance crashed with <reason:out-of-memory>",
		},
	}, {
		name:      "an empty reason keeps an empty qualifier",
		principal: nil,
		reason:    "",
		want: identity{
			Name:        "sys_crash",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{""},
			Description: "Instance crashed with <reason:>",
		},
	}, {
		name:      "the principal is ignored",
		principal: principal,
		reason:    "out-of-memory",
		want: identity{
			Name:        "sys_crash",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"out-of-memory"},
			Description: "Instance crashed with <reason:out-of-memory>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(build(event.SystemCrash(test.reason), test.principal), qt.DeepEquals, test.want)
		})
	}
}

func TestSystemMonitoringDisabled(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		principal *seclog.Principal
		monitor   string
		want      identity
	}{{
		name:      "no principal",
		principal: nil,
		monitor:   "antivirus",
		want: identity{
			Name:        "sys_monitor_disabled",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"unknown", "antivirus"},
			Description: "User unknown disabled <monitor:antivirus>",
		},
	}, {
		name:      "with principal",
		principal: principal,
		monitor:   "antivirus",
		want: identity{
			Name:        "sys_monitor_disabled",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{"<account:username1>", "antivirus"},
			Description: "User <account:username1> disabled <monitor:antivirus>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			got := build(event.SystemMonitoringDisabled(test.monitor), test.principal)
			c.Assert(got, qt.DeepEquals, test.want)
		})
	}
}

func TestUserCreated(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name       string
		principal  *seclog.Principal
		newUserID  string
		attributes []string
		want       identity
	}{{
		name:       "no principal and no attributes",
		principal:  nil,
		newUserID:  "user1",
		attributes: nil,
		want: identity{
			Name:        "user_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown", "user1", ""},
			Description: "User unknown created <user:user1> with <attributes:>",
		},
	}, {
		name:       "with principal and attributes",
		principal:  principal,
		newUserID:  "user1",
		attributes: []string{"admin", "billing"},
		want: identity{
			Name:        "user_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"<account:username1>", "user1", "admin,billing"},
			Description: "User <account:username1> created <user:user1> with <attributes:admin,billing>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			got := build(event.UserCreated(test.newUserID, test.attributes...), test.principal)
			c.Assert(got, qt.DeepEquals, test.want)
		})
	}
}

func TestUserUpdated(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name       string
		principal  *seclog.Principal
		onUserID   string
		attributes []string
		want       identity
	}{{
		name:       "no principal and no attributes",
		principal:  nil,
		onUserID:   "user1",
		attributes: nil,
		want: identity{
			Name:        "user_updated",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown", "user1", ""},
			Description: "User unknown updated <user:user1> with <attributes:>",
		},
	}, {
		name:       "with principal and attributes",
		principal:  principal,
		onUserID:   "user1",
		attributes: []string{"admin", "billing"},
		want: identity{
			Name:        "user_updated",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"<account:username1>", "user1", "admin,billing"},
			Description: "User <account:username1> updated <user:user1> with <attributes:admin,billing>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			got := build(event.UserUpdated(test.onUserID, test.attributes...), test.principal)
			c.Assert(got, qt.DeepEquals, test.want)
		})
	}
}

// TestVariadicArgumentsAreSnapshot asserts that the constructors taking
// variadic values join them at construction time, so that mutating the
// caller's slice afterwards cannot change the logged event.
func TestVariadicArgumentsAreSnapshot(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		construct func(values []string) seclog.EventFunc
		values    []string
		want      identity
	}{{
		name: "AuthenticationTokenCreated",
		construct: func(values []string) seclog.EventFunc {
			return event.AuthenticationTokenCreated(values...)
		},
		values: []string{"read", "write"},
		want: identity{
			Name:        "authn_token_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown", "read,write"},
			Description: "A token has been created for unknown with entitlements <read,write>",
		},
	}, {
		name: "UserCreated",
		construct: func(values []string) seclog.EventFunc {
			return event.UserCreated("user1", values...)
		},
		values: []string{"admin", "billing"},
		want: identity{
			Name:        "user_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown", "user1", "admin,billing"},
			Description: "User unknown created <user:user1> with <attributes:admin,billing>",
		},
	}, {
		name: "UserUpdated",
		construct: func(values []string) seclog.EventFunc {
			return event.UserUpdated("user1", values...)
		},
		values: []string{"admin", "billing"},
		want: identity{
			Name:        "user_updated",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{"unknown", "user1", "admin,billing"},
			Description: "User unknown updated <user:user1> with <attributes:admin,billing>",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			values := append([]string(nil), test.values...)
			eventFunc := test.construct(values)
			values[0] = "mutated"

			c.Assert(build(eventFunc, nil), qt.DeepEquals, test.want)
		})
	}
}

// TestECSClassification asserts the ECS metadata of every constructor. The
// values must come from the constrained ECS vocabularies.
func TestECSClassification(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name  string
		event seclog.EventFunc
		want  classification
	}{{
		name:  "AuthenticationLoginSuccess",
		event: event.AuthenticationLoginSuccess(),
		want:  ecs("user-login", "authentication", "access", seclog.OutcomeSuccess),
	}, {
		name:  "AuthenticationLoginFail",
		event: event.AuthenticationLoginFail(),
		want:  ecs("user-login", "authentication", "access", seclog.OutcomeFailure),
	}, {
		name:  "AuthenticationLoginFailMaxTries",
		event: event.AuthenticationLoginFailMaxTries(3),
		want:  ecs("user-login-failure-limit", "authentication", "denied", seclog.OutcomeFailure),
	}, {
		name:  "AuthenticationLoginLock",
		event: event.AuthenticationLoginLock(event.LoginLockReasonMaxRetries),
		want:  ecs("user-account-lock", "iam", "change", seclog.OutcomeSuccess),
	}, {
		name:  "AuthenticationPasswordChange",
		event: event.AuthenticationPasswordChange(),
		want:  ecs("user-password-change", "iam", "change", seclog.OutcomeSuccess),
	}, {
		name:  "AuthenticationPasswordChangeFail",
		event: event.AuthenticationPasswordChangeFail(),
		want:  ecs("user-password-change", "iam", "change", seclog.OutcomeFailure),
	}, {
		name:  "AuthenticationTokenCreated",
		event: event.AuthenticationTokenCreated("read"),
		want:  ecs("user-token-create", "iam", "creation", seclog.OutcomeSuccess),
	}, {
		name:  "AuthenticationTokenRevoked",
		event: event.AuthenticationTokenRevoked("token1"),
		want:  ecs("user-token-revoke", "iam", "deletion", seclog.OutcomeSuccess),
	}, {
		name:  "AuthenticationTokenReuse",
		event: event.AuthenticationTokenReuse("token1"),
		want:  ecs("user-token-reuse", "authentication", "denied", seclog.OutcomeFailure),
	}, {
		name:  "AuthenticationTokenDelete",
		event: event.AuthenticationTokenDelete(),
		want:  ecs("user-token-delete", "iam", "deletion", seclog.OutcomeSuccess),
	}, {
		name:  "AuthorizationFail",
		event: event.AuthorizationFail("database"),
		want:  ecs("authorization-check", "iam", "denied", seclog.OutcomeFailure),
	}, {
		name:  "AuthorizationAdmin uses the caller's action",
		event: event.AuthorizationAdmin("user-delete", "removed user1"),
		want:  ecs("user-delete", "iam", "admin", seclog.OutcomeUnknown),
	}, {
		name:  "SystemStartup",
		event: event.SystemStartup(),
		want:  ecs("system-start", "process", "start", seclog.OutcomeSuccess),
	}, {
		name:  "SystemShutdown",
		event: event.SystemShutdown(),
		want:  ecs("system-stop", "process", "end", seclog.OutcomeSuccess),
	}, {
		name:  "SystemRestart",
		event: event.SystemRestart(),
		want:  ecs("system-restart", "process", "change", seclog.OutcomeSuccess),
	}, {
		name:  "SystemCrash",
		event: event.SystemCrash("out-of-memory"),
		want:  ecs("system-crash", "process", "error", seclog.OutcomeFailure),
	}, {
		name:  "SystemMonitoringDisabled",
		event: event.SystemMonitoringDisabled("antivirus"),
		want:  ecs("monitoring-disable", "host", "change", seclog.OutcomeSuccess),
	}, {
		name:  "UserCreated",
		event: event.UserCreated("user1"),
		want:  ecs("user-create", "iam", "creation", seclog.OutcomeSuccess),
	}, {
		name:  "UserUpdated",
		event: event.UserUpdated("user1"),
		want:  ecs("user-update", "iam", "change", seclog.OutcomeSuccess),
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(classify(test.event), qt.DeepEquals, test.want)
		})
	}
}

// TestOWASPEventValue asserts the rendered OWASP event value of the
// constructors, including the edge cases of empty qualifiers.
func TestOWASPEventValue(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name  string
		event seclog.EventFunc
		want  string
	}{{
		name:  "an empty crash reason keeps a trailing separator",
		event: event.SystemCrash(""),
		want:  "sys_crash:",
	}, {
		name:  "a token with no entitlements keeps a trailing comma",
		event: event.AuthenticationTokenCreated(),
		want:  "authn_token_created:unknown,",
	}, {
		name:  "a user created with no attributes keeps a trailing comma",
		event: event.UserCreated("user1"),
		want:  "user_created:unknown,user1,",
	}, {
		name:  "a login success renders the principal",
		event: event.AuthenticationLoginSuccess(),
		want:  "authn_login_success:unknown",
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(logEventValue(test.event), qt.Equals, test.want)
		})
	}
}

// logEventValue emits the event with the OWASP model and returns the value of
// its event field.
func logEventValue(eventFunc seclog.EventFunc) string {
	var buffer bytes.Buffer
	logger := seclog.NewLogger("my-app", seclog.WithHandler(seclog.NewOWASPHandler(&buffer)))
	logger.Log(context.Background(), eventFunc)

	record := map[string]any{}
	if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &record); err != nil {
		panic(err)
	}
	value, _ := record["event"].(string)
	return value
}
