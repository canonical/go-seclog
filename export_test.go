// Copyright 2026 Canonical Ltd.

package seclog

import (
	"context"
	"log/slog"
)

// FieldsFromContext exposes fieldsFromContext for tests.
func FieldsFromContext(ctx context.Context) *Fields {
	return fieldsFromContext(ctx)
}

// PrincipalFromContext exposes principalFromContext for tests.
func PrincipalFromContext(ctx context.Context) *Principal {
	return principalFromContext(ctx)
}

// Merge exposes Fields.merge for tests.
func (f Fields) Merge(override Fields) Fields {
	return f.merge(override)
}

// FormatOWASPEvent exposes formatOWASPEvent for tests.
func FormatOWASPEvent(event Event) string {
	return formatOWASPEvent(event)
}

// AppID exposes the logger's application ID for tests.
func (l *Logger) AppID() string {
	return l.appID
}

// Model exposes the logger's model for tests.
func (l *Logger) Model() Model {
	return l.model
}

// DefaultFields exposes the logger's default fields for tests.
func (l *Logger) DefaultFields() Fields {
	return l.fields
}

// Handler exposes the logger's handler for tests.
func (l *Logger) Handler() slog.Handler {
	return l.handler
}

// ErrorHandler exposes the logger's error handler for tests.
func (l *Logger) ErrorHandler() func(error) {
	return l.errorHandler
}

// SetDefaultLogger replaces the package-level logger and returns the previous
// one, so that tests can restore it.
func SetDefaultLogger(logger *Logger) *Logger {
	return defaultLogger.Swap(logger)
}
