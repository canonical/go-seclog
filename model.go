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
	"io"
	"log/slog"
)

// Severity is the security significance of an event. It is distinct from the
// slog level of the record, which is always slog.LevelInfo.
type Severity string

const (
	// SeverityInfo marks an expected event that is worth recording.
	SeverityInfo Severity = "INFO"
	// SeverityWarn marks an event that may need attention.
	SeverityWarn Severity = "WARN"
	// SeverityCritical marks an event that needs immediate attention.
	SeverityCritical Severity = "CRITICAL"
)

// Outcome is the model-neutral result of an event. The values match the ECS
// event.outcome vocabulary.
type Outcome string

const (
	// OutcomeSuccess marks an event that achieved its goal.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure marks an event that did not achieve its goal.
	OutcomeFailure Outcome = "failure"
	// OutcomeUnknown marks an event whose result cannot be determined.
	OutcomeUnknown Outcome = "unknown"
)

// KindEvent is the ECS event.kind value used by every event produced by this
// package.
const KindEvent = "event"

// TypeSecurity is the value of the OWASP type field, which distinguishes
// security records from ordinary application records.
const TypeSecurity = "security"

// Event is a model-neutral security event. It carries both the stable OWASP
// identity and the ECS classification of the event, so that each Model can
// emit the representation of its own schema.
//
// Events are produced by the constructors in
// github.com/canonical/go-seclog/event, as the identifiers and wording are
// part of the package contract.
type Event struct {
	// Name is the stable package event identifier, such as
	// "authn_login_success". The OWASP model emits it as event.
	Name string

	// Action is the model-neutral action. The ECS model emits it as
	// event.action.
	Action string

	// Categories and Types use the constrained ECS vocabularies. The OWASP
	// model does not emit them.
	//
	// The built-in constructors share one package-level slice per
	// vocabulary value, so these slices must be treated as read-only.
	Categories []string
	Types      []string

	// Outcome is used by models that represent success and failure
	// explicitly. The ECS model emits it as event.outcome.
	Outcome Outcome

	// Kind is the ECS event kind. The OWASP model does not emit it.
	Kind string

	// Severity is the security significance of the event. The OWASP model
	// emits its textual value; the ECS model maps it to the package's
	// numeric convention.
	Severity Severity

	// Qualifiers are short additional qualifiers for the event identifier:
	// an account name, a token ID, or a number of failed attempts. The
	// OWASP model appends them to Name, joined by commas, without escaping
	// the separators; see the package data policy.
	Qualifiers []string

	// Description is the human-readable event message. It is emitted as the
	// record message by every model.
	Description string

	// Reason is an optional structured explanation of the outcome. The ECS
	// model emits it as event.reason; the OWASP model carries the same
	// information in Qualifiers.
	Reason string
}

// EventContext carries the resolved values that an event constructor may need
// at log time. It is a struct so that new members can be added without
// breaking existing constructors.
type EventContext struct {
	// Principal is the actor resolved from the logging context. It may be
	// nil; a nil principal renders as "unknown".
	Principal *Principal

	// Fields is the merged field set for this log call.
	Fields Fields
}

// EventFunc constructs an Event once the logger has resolved the principal and
// merged the fields for a log call. Construction is deferred so that a
// description is not formatted when the handler is disabled, and so that each
// event can place the principal at the position it requires.
type EventFunc func(ec EventContext) Event

// Model owns the output field names and structure of a log record. It receives
// the resolved principal and the merged Fields value, and may ignore anything
// that is not meaningful for its schema.
//
// The package provides NewOWASPModel and NewECSModel. Applications may
// implement this interface to support another schema.
type Model interface {
	// Name identifies the model for diagnostics and documentation.
	Name() string

	// AppendAttrs appends the model-specific attributes for one record to
	// dst and returns the extended slice. It must not mutate its arguments,
	// and must not return attributes owned by the handler, such as the
	// timestamp or the message. The principal may be nil.
	AppendAttrs(
		dst []slog.Attr,
		appID string,
		event Event,
		principal *Principal,
		fields Fields,
	) []slog.Attr
}

// HandlerProvider may be implemented by a Model to supply the slog.Handler
// used when NewLogger is called without WithHandler. Both built-in models
// implement it. A model that does not implement it gets a plain JSON
// handler with the default slog keys.
type HandlerProvider interface {
	// NewHandler returns a handler writing this model's representation to w.
	NewHandler(w io.Writer) slog.Handler
}
