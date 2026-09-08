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

// LoggerFromContext exposes loggerFromContext for tests.
func LoggerFromContext(ctx context.Context) *Logger {
	return loggerFromContext(ctx)
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
