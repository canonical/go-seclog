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

import (
	"context"
	"strings"
)

// unknownPrincipal is the rendering used by the OWASP profile when no
// principal information is available.
const unknownPrincipal = "unknown"

// Principal identifies the main actor performing an action on a resource.
//
// Only the populated members are rendered by String, joined with a comma in a
// fixed order. When no member is populated, the principal renders as unknown.
//
// By default there is no sanitization: the members are rendered as they are
// given. Sanitize any member that comes from an untrusted source, such as the
// account name of a failed login, or configure a sanitizer with
// WithSanitizer, which the logger applies to every member before rendering.
//
// e.g.:
//
//	Account: "user123", ServiceAccount: "service123"
//		-> "<account:user123,service_account:service123>"
type Principal struct {
	// Account is the account or login identifier of the actor.
	// Rendered as <account:__>. ECS: user.name.
	Account string

	// ServiceAccount is the service identity acting in this event.
	// Rendered as <service_account:__>. ECS: user.name when Account is
	// empty, otherwise user.effective.name.
	ServiceAccount string

	// Email is the actor's email address.
	// Rendered as <email:__>. ECS: user.email.
	Email string

	// Name is the actor's human-readable display name.
	// Rendered as <name:__>. ECS: user.full_name.
	Name string
}

// sanitized returns a copy of p with every member passed through sanitizer, so
// that the principal seen by the models and by the event constructors is
// already safe to render.
//
// A nil receiver, an empty principal or a nil sanitizer returns the receiver
// unchanged.
func (p *Principal) sanitized(sanitizer Sanitizer) *Principal {
	if sanitizer == nil || p.isEmpty() {
		return p
	}

	return &Principal{
		Account:        sanitizer.Sanitize(p.Account),
		ServiceAccount: sanitizer.Sanitize(p.ServiceAccount),
		Email:          sanitizer.Sanitize(p.Email),
		Name:           sanitizer.Sanitize(p.Name),
	}
}

// String renders the principal for the OWASP profile. A nil receiver, or a
// principal with no populated member, renders as unknown.
func (p *Principal) String() string {
	if p.isEmpty() {
		return unknownPrincipal
	}
	// To add one more field:
	//   Add its length to keys;
	//   Add one to separators;
	//   Add its length to the builder's capacity;
	//   Add as writePrincipalFragment.

	const keys = len("account:") + len("service_account:") + len("email:") + len("name:")
	const separators = 3
	var b strings.Builder
	b.Grow(len("<>") + keys + separators +
		len(p.Account) + len(p.ServiceAccount) + len(p.Email) + len(p.Name))

	b.WriteByte('<')
	writePrincipalFragment(&b, "account:", p.Account)
	writePrincipalFragment(&b, "service_account:", p.ServiceAccount)
	writePrincipalFragment(&b, "email:", p.Email)
	// Name is rendered last so that values rendered by earlier versions of
	// this package are unchanged.
	writePrincipalFragment(&b, "name:", p.Name)
	b.WriteByte('>')

	return b.String()
}

// writePrincipalFragment writes "key:value" to b, preceded by a comma when b
// already holds a fragment. An empty value writes nothing.
func writePrincipalFragment(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	if b.Len() > len("<") {
		b.WriteByte(',')
	}
	b.WriteString(key)
	b.WriteString(value)
}

// isEmpty reports whether the principal carries no information at all.
func (p *Principal) isEmpty() bool {
	return p == nil || *p == Principal{}
}

type principalContextKey struct{}

// ContextWithPrincipal returns a copy of ctx carrying the given principal,
// replacing any principal previously stored in ctx. A nil principal leaves
// ctx unchanged. The parent context is never modified.
//
// A nil context is treated as context.Background.
func ContextWithPrincipal(ctx context.Context, principal *Principal) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if principal == nil {
		return ctx
	}

	stored := *principal
	return context.WithValue(ctx, principalContextKey{}, &stored)
}

// principalFromContext extracts the principal stored in ctx, or nil when none
// is present. The returned value must be treated as immutable.
func principalFromContext(ctx context.Context) *Principal {
	principal, _ := ctx.Value(principalContextKey{}).(*Principal)
	return principal
}
