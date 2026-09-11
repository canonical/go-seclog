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
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// defaultAppID is the application ID used when none is configured, so that
// records are still emitted in a valid shape and stay attributable.
const defaultAppID = "unknown"

// attrsCapacity is the initial capacity used when collecting the attributes of
// one record, large enough that models rarely need to grow the slice.
const attrsCapacity = 24

// config holds the values collected by the options before a Logger is built.
type config struct {
	fields       Fields
	model        Model
	writer       io.Writer
	handler      slog.Handler
	sanitizer    Sanitizer
	errorHandler func(error)
}

// Option configures a Logger at construction time. Options are applied in
// order and each one replaces the previous value for its setting; two
// WithFields calls do not merge, the last one wins.
type Option func(*config)

// WithFields sets the default fields of the logger. They are included in every
// record emitted by the logger, and are overridden field by field by the
// context fields and by the per-call fields of LogWith.
func WithFields(fields Fields) Option {
	return func(c *config) {
		c.fields = fields
	}
}

// WithModel selects the model that owns the output field names and structure.
// The default is the OWASP model. A nil model is ignored and keeps the current
// value.
func WithModel(model Model) Option {
	return func(c *config) {
		if model != nil {
			c.model = model
		}
	}
}

// WithSanitizer sets the sanitizer applied to the user-controlled values of
// every record: the members of the Principal, and the event values that the
// constructors sanitize.
//
//	logger := seclog.NewLogger("my-app",
//		seclog.WithSanitizer(seclog.NewDefaultSanitizer(64)),
//	)
//
// Without it there is no sanitization, and the values are rendered as they are
// given. A nil sanitizer is ignored and keeps the current value.
func WithSanitizer(sanitizer Sanitizer) Option {
	return func(c *config) {
		if sanitizer != nil {
			c.sanitizer = sanitizer
		}
	}
}

// WithWriter sets the destination of the records, keeping the handler of the
// selected model, so the output keeps the model's envelope.
//
//	logger := seclog.NewLogger("my-app",
//		seclog.WithModel(seclog.NewECSModel()),
//		seclog.WithWriter(file), // still emits @timestamp and message
//	)
//
// The writer is used only when no handler is given; WithHandler always wins,
// regardless of option order. A nil writer is ignored and keeps the current
// value.
func WithWriter(w io.Writer) Option {
	return func(c *config) {
		if w != nil {
			c.writer = w
		}
	}
}

// WithHandler sets the slog handler that emits the records, mainly for tests
// and for integrating with an existing handler. Without it, the logger uses
// the handler of the selected model writing JSON to the configured writer,
// os.Stdout by default. The explicit handler always wins, regardless of option
// order, and makes WithWriter ineffective.
//
// A custom handler keeps only the attributes that the model supplies, not the
// output envelope: the timestamp, the message and the level are emitted with
// the keys of that handler. To keep the envelope, use WithWriter, or compose
// NewOWASPHandler or NewECSHandler.
//
// A nil handler is ignored and keeps the current value.
func WithHandler(handler slog.Handler) Option {
	return func(c *config) {
		if handler != nil {
			c.handler = handler
		}
	}
}

// WithErrorHandler sets the function called when the slog handler fails to
// emit a record, so that the application can report the lost security event.
//
// The function is called synchronously, once per failed record, from the
// goroutine that called Log or LogWith, and the remaining events of the call
// are still emitted. It must be safe for concurrent use, must not block, and
// must not log the same event again, as that could fail in the same way.
// Without this option, handler errors are discarded.
//
//	logger := seclog.NewLogger("my-app",
//		seclog.WithErrorHandler(func(err error) {
//			seclogFailures.Inc()
//		}),
//	)
//
// A nil function is ignored and keeps the current value.
func WithErrorHandler(errorHandler func(error)) Option {
	return func(c *config) {
		if errorHandler != nil {
			c.errorHandler = errorHandler
		}
	}
}

// Logger emits security events for one application. Its configuration is
// immutable after construction, so it is safe for concurrent use and cannot
// change while another goroutine is logging.
type Logger struct {
	appID        string
	fields       Fields
	model        Model
	handler      slog.Handler
	sanitizer    Sanitizer
	errorHandler func(error)
}

// NewLogger creates a logger for the given application ID.
//
// Without options, the logger uses the OWASP model and writes JSON to
// os.Stdout.
//
//	logger := seclog.NewLogger(
//		"my-app",
//		seclog.WithFields(seclog.Fields{Region: "us-east-1"}),
//		seclog.WithModel(seclog.NewOWASPModel()),
//	)
//
// An empty application ID becomes "unknown", so that records stay routable
// and attributable. A nil option is ignored.
func NewLogger(appID string, options ...Option) *Logger {
	if appID == "" {
		appID = defaultAppID
	}

	cfg := config{model: NewOWASPModel()}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	if cfg.handler == nil {
		cfg.handler = defaultHandler(cfg.model, cfg.writer)
	}

	return &Logger{
		appID:        appID,
		fields:       cfg.fields,
		model:        cfg.model,
		handler:      cfg.handler,
		sanitizer:    cfg.sanitizer,
		errorHandler: cfg.errorHandler,
	}
}

// defaultHandler returns the handler that the model provides for w, or a plain
// JSON handler on w when the model does not implement HandlerProvider. A nil
// writer means os.Stdout.
func defaultHandler(model Model, w io.Writer) slog.Handler {
	if w == nil {
		w = os.Stdout
	}
	if provider, ok := model.(HandlerProvider); ok {
		return provider.NewHandler(w)
	}
	return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
}

// Log emits one record per event, using the principal and the fields stored in
// ctx.
//
// Each event is emitted individually and as it was constructed. Use the
// constructors in github.com/canonical/go-seclog/event to create them.
//
// To add fields to the record, see WithFields and ContextWithFields. To set the
// actor of the event, see ContextWithPrincipal and LogWith.
//
// A nil context is treated as context.Background, and a nil logger discards
// the events, so that an optional logger can be used without a nil check.
func (l *Logger) Log(ctx context.Context, events ...EventFunc) {
	if l == nil || len(events) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if !l.handler.Enabled(ctx, slog.LevelInfo) {
		return
	}

	principal := principalFromContext(ctx).sanitized(l.sanitizer)

	fields := l.fields
	if contextFields := fieldsFromContext(ctx); contextFields != nil {
		fields = fields.merge(*contextFields)
	}

	// The principal and the fields are resolved once per call, so every
	// event of this call observes exactly the same context.
	ec := EventContext{Principal: principal, Fields: fields, Sanitizer: l.sanitizer}
	for _, eventFunc := range events {
		if eventFunc == nil {
			continue
		}
		event := eventFunc(ec)

		attrs := l.model.AppendAttrs(
			make([]slog.Attr, 0, attrsCapacity),
			l.appID,
			event,
			principal,
			fields,
		)

		// Security records are always emitted at INFO; the model reports
		// the significance of the event instead. The PC is 0, so
		// AddSource emits no "source": Log is reached at several call
		// depths, so no single skip value fits all of them.
		record := slog.NewRecord(time.Now(), slog.LevelInfo, event.Description, 0)
		record.AddAttrs(attrs...)
		if err := l.handler.Handle(ctx, record); err != nil && l.errorHandler != nil {
			l.errorHandler(err)
		}
	}
}

// LogWith emits events with the given principal and fields, without requiring
// the caller to build a context first.
//
// A non-nil principal replaces the principal in ctx, a nil one keeps it, and
// &Principal{} logs an unknown actor explicitly. The fields override the
// matching non-zero members of the logger and context fields.
//
// A nil context is treated as context.Background and a nil logger discards the
// events, as in Log.
func (l *Logger) LogWith(
	ctx context.Context,
	principal *Principal,
	fields Fields,
	events ...EventFunc,
) {
	if l == nil {
		return
	}

	ctx = ContextWithPrincipal(ctx, principal)
	ctx = ContextWithFields(ctx, fields)
	l.Log(ctx, events...)
}

type loggerContextKey struct{}

// ContextWithLogger returns a copy of ctx carrying the given logger, replacing
// any logger previously stored in ctx. A nil logger leaves ctx unchanged. The
// parent context is never modified.
//
// The package-level Log and LogWith use the logger stored in the context, so
// that code called with that context logs with the identity and the
// configuration chosen by its caller, without being given a logger:
//
//	ctx = seclog.ContextWithLogger(ctx, seclog.NewLogger("my-app"))
//	seclog.Log(ctx, event.SystemStartup()) // logs as "my-app"
//
// The methods of a Logger always use their receiver and ignore the logger
// stored in the context.
//
// The logger is stored as it is, not copied: its configuration is immutable,
// so the stored logger cannot change while another goroutine is logging.
//
// A nil context is treated as context.Background.
func ContextWithLogger(ctx context.Context, logger *Logger) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		return ctx
	}

	return context.WithValue(ctx, loggerContextKey{}, logger)
}

// loggerFromContext extracts the logger stored in ctx, or nil when none is
// present. A nil context carries no logger.
func loggerFromContext(ctx context.Context) *Logger {
	if ctx == nil {
		return nil
	}

	logger, _ := ctx.Value(loggerContextKey{}).(*Logger)
	return logger
}

// defaultLogger is the logger used by the package-level functions. It is
// replaced atomically by Setup, so concurrent setup and logging never observe
// a partially updated configuration.
var defaultLogger atomic.Pointer[Logger]

func init() {
	defaultLogger.Store(NewLogger(defaultAppID))
}

// Setup replaces the configuration of the package-level logger.
//
// Use it when the process has a single application ID and uses the
// package-level functions; otherwise create a logger with NewLogger and give
// it to the code that logs, either directly or in the context with
// ContextWithLogger. Until Setup is called, the package-level logger uses the
// application ID "unknown" and the OWASP model. An empty application ID also
// becomes "unknown".
//
//	seclog.Setup("my-app",
//		seclog.WithFields(seclog.Fields{Region: "us-east-1"}),
//		seclog.WithModel(seclog.NewOWASPModel()),
//	)
//	seclog.Log(ctx, event.SystemStartup()) // logs as "my-app"
func Setup(appID string, options ...Option) {
	defaultLogger.Store(NewLogger(appID, options...))
}

// contextLoggerOrDefault returns the logger stored in ctx, or the
// package-level logger when ctx carries none.
func contextLoggerOrDefault(ctx context.Context) *Logger {
	if logger := loggerFromContext(ctx); logger != nil {
		return logger
	}
	return defaultLogger.Load()
}

// Log emits one record per event with the logger stored in ctx by
// ContextWithLogger, or with the package-level logger when ctx carries none,
// using the principal and the fields stored in ctx. See Logger.Log.
func Log(ctx context.Context, events ...EventFunc) {
	contextLoggerOrDefault(ctx).Log(ctx, events...)
}

// LogWith emits events with the logger stored in ctx by ContextWithLogger, or
// with the package-level logger when ctx carries none, using the given
// principal and fields. See Logger.LogWith.
func LogWith(
	ctx context.Context,
	principal *Principal,
	fields Fields,
	events ...EventFunc,
) {
	contextLoggerOrDefault(ctx).LogWith(ctx, principal, fields, events...)
}
