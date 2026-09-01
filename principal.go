// Copyright 2026 Canonical Ltd.

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
// The members are rendered as they are given and are never escaped or
// validated. Sanitize any member that comes from an untrusted source,
// such as the account name of a failed login, or use the ECS model,
// which emits the members as their own JSON fields instead.
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
func ContextWithPrincipal(ctx context.Context, principal *Principal) context.Context {
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
