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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/canonical/go-seclog"
	qt "github.com/frankban/quicktest"
)

func TestNewLogger(t *testing.T) {
	c := qt.New(t)

	handler := newRecordingHandler()

	tests := []struct {
		name             string
		appID            string
		options          []seclog.Option
		wantAppID        string
		wantFields       seclog.Fields
		wantModel        seclog.Model
		wantHandler      slog.Handler
		wantSanitizer    bool
		wantErrorHandler bool
	}{{
		name:      "defaults to the OWASP model",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   nil,
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:       "default fields",
		appID:      testAppID,
		wantAppID:  testAppID,
		options:    []seclog.Option{seclog.WithFields(seclog.Fields{Region: "us-east-1"})},
		wantFields: seclog.Fields{Region: "us-east-1"},
		wantModel:  seclog.NewOWASPModel(),
	}, {
		name:      "repeated options replace each other",
		appID:     testAppID,
		wantAppID: testAppID,
		options: []seclog.Option{
			seclog.WithFields(seclog.Fields{Region: "us-east-1"}),
			seclog.WithFields(seclog.Fields{HostName: "host-1"}),
		},
		wantFields: seclog.Fields{HostName: "host-1"},
		wantModel:  seclog.NewOWASPModel(),
	}, {
		name:      "explicit model",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   []seclog.Option{seclog.WithModel(seclog.NewECSModel())},
		wantModel: seclog.NewECSModel(),
	}, {
		name:      "a nil model keeps the default",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   []seclog.Option{seclog.WithModel(nil)},
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:      "an explicit handler wins regardless of option order",
		appID:     testAppID,
		wantAppID: testAppID,
		options: []seclog.Option{
			seclog.WithHandler(handler),
			seclog.WithModel(seclog.NewECSModel()),
		},
		wantModel:   seclog.NewECSModel(),
		wantHandler: handler,
	}, {
		name:      "a nil handler keeps the model handler",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   []seclog.Option{seclog.WithHandler(nil)},
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:      "a nil writer keeps the default destination",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   []seclog.Option{seclog.WithWriter(nil)},
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:      "an explicit handler wins over a writer",
		appID:     testAppID,
		wantAppID: testAppID,
		options: []seclog.Option{
			seclog.WithWriter(&bytes.Buffer{}),
			seclog.WithHandler(handler),
		},
		wantModel:   seclog.NewOWASPModel(),
		wantHandler: handler,
	}, {
		name:             "explicit error handler",
		appID:            testAppID,
		wantAppID:        testAppID,
		options:          []seclog.Option{seclog.WithErrorHandler(func(error) {})},
		wantModel:        seclog.NewOWASPModel(),
		wantErrorHandler: true,
	}, {
		name:      "a nil error handler keeps the default",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   []seclog.Option{seclog.WithErrorHandler(nil)},
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:          "explicit sanitizer",
		appID:         testAppID,
		wantAppID:     testAppID,
		options:       []seclog.Option{seclog.WithSanitizer(seclog.NewDefaultSanitizer(64))},
		wantModel:     seclog.NewOWASPModel(),
		wantSanitizer: true,
	}, {
		name:      "no sanitizer by default",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   nil,
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:      "a nil sanitizer keeps the default",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   []seclog.Option{seclog.WithSanitizer(nil)},
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:      "an empty application ID becomes unknown",
		appID:     "",
		wantAppID: "unknown",
		options:   nil,
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:      "nil options are ignored",
		appID:     testAppID,
		wantAppID: testAppID,
		options:   []seclog.Option{nil},
		wantModel: seclog.NewOWASPModel(),
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			logger := seclog.NewLogger(test.appID, test.options...)

			c.Assert(logger.AppID(), qt.Equals, test.wantAppID)
			c.Assert(logger.DefaultFields(), qt.DeepEquals, test.wantFields)
			c.Assert(logger.Model(), qt.Equals, test.wantModel)
			c.Assert(logger.Handler(), qt.IsNotNil)
			c.Assert(logger.Sanitizer() != nil, qt.Equals, test.wantSanitizer)
			c.Assert(logger.ErrorHandler() != nil, qt.Equals, test.wantErrorHandler)
			assertHandler(c, logger, test.wantHandler)
		})
	}
}

func TestLog(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name          string
		appID         string
		principal     *seclog.Principal
		defaultFields seclog.Fields
		contextFields seclog.Fields
		events        []seclog.Event
		want          []map[string]any
	}{{
		name:   "empty events",
		appID:  testAppID,
		events: nil,
		want:   nil,
	}, {
		name:   "one event",
		appID:  testAppID,
		events: []seclog.Event{{Name: "sometype", Severity: seclog.SeverityInfo}},
		want:   []map[string]any{owaspRecord("sometype", "", "INFO", nil)},
	}, {
		name:  "multiple events are emitted individually",
		appID: testAppID,
		events: []seclog.Event{
			{Name: "sometype1", Severity: seclog.SeverityInfo},
			{Name: "sometype2", Severity: seclog.SeverityWarn},
		},
		want: []map[string]any{
			owaspRecord("sometype1", "", "INFO", nil),
			owaspRecord("sometype2", "", "WARN", nil),
		},
	}, {
		name:  "event with description",
		appID: testAppID,
		events: []seclog.Event{
			{Name: "mytype", Severity: seclog.SeverityWarn, Description: "mydescription"},
		},
		want: []map[string]any{owaspRecord("mytype", "mydescription", "WARN", nil)},
	}, {
		name:  "logger with no app ID",
		appID: "",
		events: []seclog.Event{
			{Name: "mytype", Severity: seclog.SeverityCritical, Description: "mydescription"},
		},
		want: []map[string]any{{
			"level":       "INFO",
			"appid":       "unknown",
			"type":        "security",
			"event":       "mytype",
			"severity":    "CRITICAL",
			"description": "mydescription",
		}},
	}, {
		name:          "logger with default fields",
		appID:         testAppID,
		defaultFields: seclog.Fields{TraceID: "my-trace-id", UserAgent: "my-user-agent"},
		events:        []seclog.Event{{Name: "mytype", Severity: seclog.SeverityInfo}},
		want: []map[string]any{owaspRecord("mytype", "", "INFO", map[string]any{
			"trace_id":  "my-trace-id",
			"useragent": "my-user-agent",
		})},
	}, {
		name:          "context fields override the default fields",
		appID:         testAppID,
		defaultFields: seclog.Fields{TraceID: "my-trace-id", UserAgent: "my-user-agent"},
		contextFields: seclog.Fields{TraceID: "my-new-trace-id", HostName: "host-1"},
		events:        []seclog.Event{{Name: "mytype", Severity: seclog.SeverityInfo}},
		want: []map[string]any{owaspRecord("mytype", "", "INFO", map[string]any{
			"trace_id":  "my-new-trace-id",
			"useragent": "my-user-agent",
			"hostname":  "host-1",
		})},
	}, {
		name:      "the principal is resolved from the context",
		appID:     testAppID,
		principal: &seclog.Principal{Account: "username1"},
		events:    []seclog.Event{{Name: "mytype", Severity: seclog.SeverityInfo}},
		want:      []map[string]any{owaspRecord("mytype", "", "INFO", nil)},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			logger, decode := jsonLogger(
				seclog.NewOWASPModel(),
				test.appID,
				seclog.WithFields(test.defaultFields),
			)

			ctx := seclog.ContextWithPrincipal(context.Background(), test.principal)
			ctx = seclog.ContextWithFields(ctx, test.contextFields)
			logger.Log(ctx, testEvents(test.events)...)

			assertRecords(c, decode, test.want)
		})
	}
}

// noHandler is used by the table rows that do not set an explicit handler.
// WithHandler ignores a nil handler, so the rows stay free of branching.
func noHandler(io.Writer) slog.Handler {
	return nil
}

// TestHandlerSelection asserts which handler emits the records, and that the
// output envelope of the selected model survives the choice.
func TestHandlerSelection(t *testing.T) {
	c := qt.New(t)

	owaspKeys := []string{
		"appid", "datetime", "description", "event", "level", "severity", "type",
	}
	ecsKeys := []string{
		"@timestamp", "event.code", "event.kind", "event.severity",
		"log.level", "message", "service.name",
	}

	tests := []struct {
		name       string
		model      seclog.Model
		newHandler func(w io.Writer) slog.Handler
		want       []string
	}{{
		name:       "the writer keeps the OWASP envelope",
		model:      seclog.NewOWASPModel(),
		newHandler: noHandler,
		want:       owaspKeys,
	}, {
		name:       "the writer keeps the ECS envelope",
		model:      seclog.NewECSModel(),
		newHandler: noHandler,
		want:       ecsKeys,
	}, {
		name:       "NewOWASPHandler keeps the OWASP envelope",
		model:      seclog.NewOWASPModel(),
		newHandler: seclog.NewOWASPHandler,
		want:       owaspKeys,
	}, {
		name:       "NewECSHandler keeps the ECS envelope",
		model:      seclog.NewECSModel(),
		newHandler: seclog.NewECSHandler,
		want:       ecsKeys,
	}, {
		name:  "an unrelated handler wins over the writer",
		model: seclog.NewECSModel(),
		newHandler: func(io.Writer) slog.Handler {
			return newRecordingHandler()
		},
		want: nil,
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			var buffer bytes.Buffer
			logger := seclog.NewLogger(testAppID,
				seclog.WithModel(test.model),
				seclog.WithWriter(&buffer),
				seclog.WithHandler(test.newHandler(&buffer)),
			)

			logger.Log(context.Background(), testEvent(seclog.Event{
				Name:     "mytype",
				Kind:     seclog.KindEvent,
				Severity: seclog.SeverityInfo,
			}))

			c.Assert(recordKeys(buffer.Bytes()), qt.DeepEquals, test.want)
		})
	}
}

// TestLogAcceptsANilContext asserts that a nil context is treated as
// context.Background, as log/slog does, rather than crashing the caller: a
// security event is never worth taking the process down for.
func TestLogAcceptsANilContext(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name string
		log  func(logger *seclog.Logger)
	}{{
		name: "Log",
		log: func(logger *seclog.Logger) {
			logger.Log(nil, principalEvent())
		},
	}, {
		name: "LogWith without a principal",
		log: func(logger *seclog.Logger) {
			logger.LogWith(nil, nil, seclog.Fields{}, principalEvent())
		},
	}, {
		name: "LogWith with a principal and fields",
		log: func(logger *seclog.Logger) {
			//lint:ignore
			logger.LogWith(nil, &seclog.Principal{Account: "user1"},
				seclog.Fields{TraceID: "trace-1"}, principalEvent())
		},
	}, {
		name: "package-level Log",
		log: func(*seclog.Logger) {
			seclog.Log(nil, principalEvent())
		},
	}, {
		name: "package-level LogWith",
		log: func(*seclog.Logger) {
			seclog.LogWith(nil, &seclog.Principal{Account: "user1"},
				seclog.Fields{TraceID: "trace-1"}, principalEvent())
		},
	}, {
		// A caller holding an optional context builds its values first,
		// so the context helpers must tolerate a nil parent as well.
		name: "values built from a nil context",
		log: func(logger *seclog.Logger) {
			ctx := seclog.ContextWithPrincipal(nil, &seclog.Principal{Account: "user1"})
			ctx = seclog.ContextWithFields(ctx, seclog.Fields{TraceID: "trace-1"})
			logger.Log(ctx, principalEvent())
		},
	}, {
		name: "zero values built from a nil context",
		log: func(logger *seclog.Logger) {
			ctx := seclog.ContextWithPrincipal(nil, nil)
			ctx = seclog.ContextWithFields(ctx, seclog.Fields{})
			logger.Log(ctx, principalEvent())
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			handler := newRecordingHandler()
			logger := seclog.NewLogger(testAppID, seclog.WithHandler(handler))
			withDefaultLogger(c, logger)

			test.log(logger)

			c.Assert(handler.Records(), qt.HasLen, 1)
		})
	}
}

// TestLogIgnoresANilLogger asserts that a nil logger discards the events
// instead of crashing the caller, so that an optional logger held by an
// application can be used without a nil check. Each case asserts that the call
// does not panic.
func TestLogIgnoresANilLogger(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name string
		log  func(logger *seclog.Logger)
	}{{
		name: "Log",
		log: func(logger *seclog.Logger) {
			logger.Log(context.Background(), principalEvent())
		},
	}, {
		name: "Log without events",
		log: func(logger *seclog.Logger) {
			logger.Log(context.Background())
		},
	}, {
		name: "Log with a nil context",
		log: func(logger *seclog.Logger) {
			logger.Log(nil, principalEvent())
		},
	}, {
		name: "LogWith",
		log: func(logger *seclog.Logger) {
			logger.LogWith(context.Background(), &seclog.Principal{Account: "user1"},
				seclog.Fields{TraceID: "trace-1"}, principalEvent())
		},
	}, {
		name: "LogWith with a nil context",
		log: func(logger *seclog.Logger) {
			logger.LogWith(nil, nil, seclog.Fields{}, principalEvent())
		},
	}, {
		// The package-level logger is never nil in practice, but the
		// package-level functions must not crash if it ever is.
		name: "package-level Log",
		log: func(*seclog.Logger) {
			seclog.Log(context.Background(), principalEvent())
		},
	}, {
		name: "package-level LogWith",
		log: func(*seclog.Logger) {
			seclog.LogWith(context.Background(), nil, seclog.Fields{}, principalEvent())
		},
	}, {
		name: "a nil logger in the context",
		log: func(*seclog.Logger) {
			ctx := seclog.ContextWithLogger(context.Background(), nil)
			seclog.Log(ctx, principalEvent())
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			withDefaultLogger(c, nil)

			test.log(nil)
		})
	}
}

// TestHandlerKeepsComposedAttributes asserts that the model handlers stay
// usable when composed with an application handler, as their documentation
// invites: an attribute that happens to use a slog built-in key belongs to the
// application and must be neither fatal nor silently dropped.
func TestHandlerKeepsComposedAttributes(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name       string
		newHandler func(w io.Writer) slog.Handler
		attrs      []any
		want       map[string]any
	}{{
		name:       "the OWASP handler keeps a textual time attribute",
		newHandler: seclog.NewOWASPHandler,
		attrs:      []any{"time", "12:00"},
		want:       map[string]any{"description": "hello", "level": "INFO", "time": "12:00"},
	}, {
		name:       "the ECS handler keeps a numeric time attribute",
		newHandler: seclog.NewECSHandler,
		attrs:      []any{"time", 5},
		want:       map[string]any{"message": "hello", "time": float64(5)},
	}, {
		name:       "the ECS handler keeps a textual level attribute",
		newHandler: seclog.NewECSHandler,
		attrs:      []any{"level", "debug"},
		want:       map[string]any{"message": "hello", "level": "debug"},
	}, {
		name:       "the ECS handler drops the record level",
		newHandler: seclog.NewECSHandler,
		attrs:      nil,
		want:       map[string]any{"message": "hello"},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			var buffer bytes.Buffer
			slog.New(test.newHandler(&buffer)).Info("hello", test.attrs...)

			c.Assert(decodeRecords(buffer.Bytes()), qt.DeepEquals, []map[string]any{test.want})
		})
	}
}

func TestLogResolvesTheContextOnce(t *testing.T) {
	c := qt.New(t)

	principal := &seclog.Principal{Account: "username1"}
	ctx := seclog.ContextWithPrincipal(context.Background(), principal)
	ctx = seclog.ContextWithFields(ctx, seclog.Fields{TraceID: "trace-1"})

	var observed []seclog.EventContext
	record := func(ec seclog.EventContext) seclog.Event {
		observed = append(observed, ec)
		return seclog.Event{Name: "mytype", Severity: seclog.SeverityInfo}
	}

	logger := seclog.NewLogger(testAppID, seclog.WithHandler(newRecordingHandler()))
	logger.Log(ctx, record, record)

	c.Assert(observed, qt.HasLen, 2)
	c.Assert(observed[0], qt.DeepEquals, observed[1])
	c.Assert(observed[0].Principal, qt.DeepEquals, principal)
	c.Assert(observed[0].Fields, qt.DeepEquals, seclog.Fields{TraceID: "trace-1"})
}

// TestWithSanitizer asserts that the configured sanitizer reaches the
// rendered principal, the event constructors and every model.
func TestWithSanitizer(t *testing.T) {
	c := qt.New(t)

	// The principal carries the OWASP delimiters, so that an unsanitized
	// rendering would forge a second account fragment.
	injected := &seclog.Principal{Account: "user1>,<account:admin", Name: "John\nDoe"}

	tests := []struct {
		name      string
		model     seclog.Model
		options   []seclog.Option
		principal *seclog.Principal
		want      map[string]any
	}{{
		name:      "without a sanitizer the members are rendered as given",
		model:     seclog.NewOWASPModel(),
		principal: injected,
		want: owaspRecord(
			"authn:<account:user1>,<account:admin,name:John\nDoe>",
			"User <account:user1>,<account:admin,name:John\nDoe>",
			"INFO", nil),
	}, {
		name:      "the OWASP rendering is sanitized",
		model:     seclog.NewOWASPModel(),
		options:   []seclog.Option{seclog.WithSanitizer(seclog.NewDefaultSanitizer(64))},
		principal: injected,
		want: owaspRecord(
			"authn:<account:user1accountadmin,name:JohnDoe>",
			"User <account:user1accountadmin,name:JohnDoe>",
			"INFO", nil),
	}, {
		name:      "a nil sanitizer keeps the members",
		model:     seclog.NewOWASPModel(),
		options:   []seclog.Option{seclog.WithSanitizer(nil)},
		principal: injected,
		want: owaspRecord(
			"authn:<account:user1>,<account:admin,name:John\nDoe>",
			"User <account:user1>,<account:admin,name:John\nDoe>",
			"INFO", nil),
	}, {
		name:      "the ECS members are sanitized",
		model:     seclog.NewECSModel(),
		options:   []seclog.Option{seclog.WithSanitizer(seclog.NewDefaultSanitizer(64))},
		principal: injected,
		want: map[string]any{
			"message":        "User <account:user1accountadmin,name:JohnDoe>",
			"service.name":   testAppID,
			"event.code":     "authn",
			"event.severity": float64(1),
			"log.level":      "INFO",
			"user.name":      "user1accountadmin",
			"user.full_name": "JohnDoe",
		},
	}, {
		name:      "the sanitizer truncates long members",
		model:     seclog.NewOWASPModel(),
		options:   []seclog.Option{seclog.WithSanitizer(seclog.NewDefaultSanitizer(4))},
		principal: &seclog.Principal{Account: "username1"},
		want: owaspRecord(
			"authn:<account:user>",
			"User <account:user>",
			"INFO", nil),
	}, {
		name:      "a principal left empty by the sanitizer is unknown",
		model:     seclog.NewOWASPModel(),
		options:   []seclog.Option{seclog.WithSanitizer(seclog.NewDefaultSanitizer(64))},
		principal: &seclog.Principal{Account: "<<>>"},
		want:      owaspRecord("authn:unknown", "User unknown", "INFO", nil),
	}}

	// The event renders the principal both as a qualifier and in its
	// description, as the built-in constructors do.
	principalEvent := func(ec seclog.EventContext) seclog.Event {
		return seclog.Event{
			Name:        "authn",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{ec.Principal.String()},
			Description: "User " + ec.Principal.String(),
		}
	}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			logger, decode := jsonLogger(test.model, testAppID, test.options...)
			ctx := seclog.ContextWithPrincipal(context.Background(), test.principal)

			logger.Log(ctx, principalEvent)

			assertRecords(c, decode, []map[string]any{test.want})
		})
	}
}

// TestLogSanitizesEventValues asserts that the sanitizer reaches the values an
// event constructor receives from the application, through EventContext.
func TestLogSanitizesEventValues(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name    string
		options []seclog.Option
		want    string
	}{{
		name: "without a sanitizer the value is kept",
		want: "resource:<admin>",
	}, {
		name:    "with a sanitizer the value is sanitized",
		options: []seclog.Option{seclog.WithSanitizer(seclog.NewDefaultSanitizer(64))},
		want:    "resourceadmin",
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			logger, decode := jsonLogger(seclog.NewOWASPModel(), testAppID, test.options...)

			logger.Log(context.Background(), func(ec seclog.EventContext) seclog.Event {
				return seclog.Event{
					Name:        "authz",
					Severity:    seclog.SeverityInfo,
					Description: ec.Sanitize("resource:<admin>"),
				}
			})

			assertRecords(c, decode, []map[string]any{
				owaspRecord("authz", test.want, "INFO", nil),
			})
		})
	}
}

// TestLogKeepsTheContextPrincipal asserts that the sanitizer is applied to a
// copy, so that the principal stored in the context is not modified and does
// not carry the sanitizer over to a later call made with another logger.
func TestLogKeepsTheContextPrincipal(t *testing.T) {
	c := qt.New(t)

	principal := &seclog.Principal{Account: "user1>,<account:admin"}
	ctx := seclog.ContextWithPrincipal(context.Background(), principal)

	sanitizing, decodeSanitized := jsonLogger(seclog.NewOWASPModel(), testAppID,
		seclog.WithSanitizer(seclog.NewDefaultSanitizer(64)))
	plain, decodePlain := jsonLogger(seclog.NewOWASPModel(), testAppID)

	principalEvent := func(ec seclog.EventContext) seclog.Event {
		return seclog.Event{
			Name:        "authn",
			Severity:    seclog.SeverityInfo,
			Description: ec.Principal.String(),
		}
	}

	sanitizing.Log(ctx, principalEvent)
	plain.Log(ctx, principalEvent)

	assertRecords(c, decodeSanitized, []map[string]any{
		owaspRecord("authn", "<account:user1accountadmin>", "INFO", nil),
	})
	// The second logger has no sanitizer, so it must still observe the
	// original members.
	assertRecords(c, decodePlain, []map[string]any{
		owaspRecord("authn", "<account:user1>,<account:admin>", "INFO", nil),
	})
	c.Assert(seclog.PrincipalFromContext(ctx), qt.DeepEquals, principal)
}

func TestLogSkipsDisabledHandlers(t *testing.T) {
	c := qt.New(t)

	evaluated := false
	handler := newDisabledHandler()
	logger := seclog.NewLogger(testAppID, seclog.WithHandler(handler))

	logger.Log(context.Background(), func(seclog.EventContext) seclog.Event {
		evaluated = true
		return seclog.Event{Name: "mytype"}
	})

	c.Assert(evaluated, qt.IsFalse)
	c.Assert(handler.Records(), qt.HasLen, 0)
}

func TestLogEmitsAtInfoLevel(t *testing.T) {
	c := qt.New(t)

	handler := newRecordingHandler()
	logger := seclog.NewLogger(testAppID, seclog.WithHandler(handler))
	logger.Log(context.Background(), testEvent(seclog.Event{
		Name:        "authn_token_reuse",
		Severity:    seclog.SeverityCritical,
		Description: "mydescription",
	}))

	records := handler.Records()
	c.Assert(records, qt.HasLen, 1)
	c.Assert(records[0].Level, qt.Equals, slog.LevelInfo)
	c.Assert(records[0].Message, qt.Equals, "mydescription")
	c.Assert(attrs(records[0])["severity"], qt.Equals, "CRITICAL")
}

func TestLogReportsHandlerErrors(t *testing.T) {
	c := qt.New(t)

	handlerErr := errors.New("handler failed")

	tests := []struct {
		name             string
		handlerErr       error
		withErrorHandler bool
		wantErrors       []string
	}{{
		name:             "no error is reported when the handler succeeds",
		handlerErr:       nil,
		withErrorHandler: true,
		wantErrors:       nil,
	}, {
		name:             "one error is reported per failed record",
		handlerErr:       handlerErr,
		withErrorHandler: true,
		wantErrors:       []string{"handler failed", "handler failed"},
	}, {
		name:             "handler errors are discarded without an error handler",
		handlerErr:       handlerErr,
		withErrorHandler: false,
		wantErrors:       nil,
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			var got []string
			handler := newFailingHandler(test.handlerErr)
			options := []seclog.Option{seclog.WithHandler(handler)}
			if test.withErrorHandler {
				options = append(options, seclog.WithErrorHandler(func(err error) {
					got = append(got, err.Error())
				}))
			}
			logger := seclog.NewLogger(testAppID, options...)

			logger.Log(
				context.Background(),
				testEvent(seclog.Event{Name: "mytype1", Severity: seclog.SeverityInfo}),
				testEvent(seclog.Event{Name: "mytype2", Severity: seclog.SeverityInfo}),
			)

			c.Assert(got, qt.DeepEquals, test.wantErrors)
			// A failing record does not stop the remaining events.
			c.Assert(handler.Records(), qt.HasLen, 2)
		})
	}
}

func TestLogWith(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name          string
		defaultFields seclog.Fields
		contextFields seclog.Fields
		principal     *seclog.Principal
		fields        seclog.Fields
		want          []map[string]any
	}{{
		name:      "with principal and fields",
		principal: &seclog.Principal{Account: "user"},
		fields:    seclog.Fields{SourceIP: "192.0.2.1"},
		want: []map[string]any{owaspRecord("mytype:<account:user>", "", "INFO", map[string]any{
			"source_ip": "192.0.2.1",
		})},
	}, {
		name:      "a nil principal keeps the context principal",
		principal: nil,
		fields:    seclog.Fields{},
		want:      []map[string]any{owaspRecord("mytype:<account:context>", "", "INFO", nil)},
	}, {
		name:          "per-call fields override the logger and context fields",
		defaultFields: seclog.Fields{TraceID: "logger", UserAgent: "logger"},
		contextFields: seclog.Fields{TraceID: "context", HostName: "context"},
		fields:        seclog.Fields{TraceID: "call"},
		want: []map[string]any{owaspRecord("mytype:<account:context>", "", "INFO", map[string]any{
			"trace_id":  "call",
			"useragent": "logger",
			"hostname":  "context",
		})},
	}, {
		name:      "the principal replaces the context principal",
		principal: &seclog.Principal{Account: "call"},
		want:      []map[string]any{owaspRecord("mytype:<account:call>", "", "INFO", nil)},
	}, {
		name:      "an empty principal logs an unknown actor",
		principal: &seclog.Principal{},
		want:      []map[string]any{owaspRecord("mytype:unknown", "", "INFO", nil)},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			logger, decode := jsonLogger(
				seclog.NewOWASPModel(),
				testAppID,
				seclog.WithFields(test.defaultFields),
			)

			ctx := seclog.ContextWithPrincipal(
				context.Background(),
				&seclog.Principal{Account: "context"},
			)
			ctx = seclog.ContextWithFields(ctx, test.contextFields)

			logger.LogWith(ctx, test.principal, test.fields, principalEvent())

			assertRecords(c, decode, test.want)
		})
	}
}

func TestSetup(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name      string
		appID     string
		options   []seclog.Option
		wantAppID string
		wantModel seclog.Model
	}{{
		name:      "app ID only",
		appID:     testAppID,
		wantAppID: testAppID,
		wantModel: seclog.NewOWASPModel(),
	}, {
		name:      "app ID and model",
		appID:     "my-other-app",
		options:   []seclog.Option{seclog.WithModel(seclog.NewECSModel())},
		wantAppID: "my-other-app",
		wantModel: seclog.NewECSModel(),
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			withDefaultLogger(c, seclog.NewLogger("previous"))
			seclog.Setup(test.appID, test.options...)

			logger := seclog.SetDefaultLogger(nil)
			seclog.SetDefaultLogger(logger)

			c.Assert(logger.AppID(), qt.Equals, test.wantAppID)
			c.Assert(logger.Model(), qt.Equals, test.wantModel)
		})
	}
}

func TestPackageLevelLog(t *testing.T) {
	c := qt.New(t)

	handler := newRecordingHandler()
	withDefaultLogger(c, seclog.NewLogger(testAppID, seclog.WithHandler(handler)))

	ctx := seclog.ContextWithPrincipal(context.Background(), &seclog.Principal{Account: "ctx"})
	seclog.Log(ctx, principalEvent())
	seclog.LogWith(ctx, &seclog.Principal{Account: "call"}, seclog.Fields{TraceID: "t"}, principalEvent())

	records := handler.Records()
	c.Assert(records, qt.HasLen, 2)
	c.Assert(attrs(records[0])["event"], qt.Equals, "mytype:<account:ctx>")
	c.Assert(attrs(records[1])["event"], qt.Equals, "mytype:<account:call>")
	c.Assert(attrs(records[1])["trace_id"], qt.Equals, "t")
}

// TestContextWithLogger asserts the logger stored in the context, which the
// package-level functions use in place of the package-level logger.
func TestContextWithLogger(t *testing.T) {
	c := qt.New(t)

	logger1 := seclog.NewLogger("my-app-1")
	logger2 := seclog.NewLogger("my-app-2")

	tests := []struct {
		name      string
		nilParent bool
		loggers   []*seclog.Logger
		want      *seclog.Logger
	}{{
		name:    "without logger",
		loggers: nil,
		want:    nil,
	}, {
		name:    "nil logger is ignored",
		loggers: []*seclog.Logger{nil},
		want:    nil,
	}, {
		name:    "with logger",
		loggers: []*seclog.Logger{logger1},
		want:    logger1,
	}, {
		name:    "logger rewrite",
		loggers: []*seclog.Logger{logger1, logger2},
		want:    logger2,
	}, {
		name:    "nil logger keeps the previous one",
		loggers: []*seclog.Logger{logger1, nil},
		want:    logger1,
	}, {
		name:      "a nil parent is treated as background",
		nilParent: true,
		loggers:   []*seclog.Logger{logger1},
		want:      logger1,
	}, {
		name:      "a nil parent with a nil logger is treated as background",
		nilParent: true,
		loggers:   []*seclog.Logger{nil},
		want:      nil,
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			ctx := context.Background()
			if test.nilParent {
				ctx = nil
			}
			for _, logger := range test.loggers {
				ctx = seclog.ContextWithLogger(ctx, logger)
			}

			// The helper never returns a nil context, so a caller that
			// builds its values before logging cannot be handed one.
			c.Assert(ctx, qt.IsNotNil)

			// The logger is stored as it is, so that the emitted
			// records use its configuration and not a copy of it.
			c.Assert(seclog.LoggerFromContext(ctx), qt.Equals, test.want)
		})
	}
}

// TestPackageLevelLogUsesTheContextLogger asserts that the package-level
// functions emit with the logger carried by the context, so that code called
// with that context logs with the configuration chosen by its caller, and fall
// back to the package-level logger when the context carries none.
func TestPackageLevelLogUsesTheContextLogger(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name            string
		buildContext    func(contextLogger, defaultLogger *seclog.Logger) context.Context
		log             func(ctx context.Context, defaultLogger *seclog.Logger)
		wantContextLogs int
		wantDefaultLogs int
	}{{
		name:            "Log uses the context logger",
		buildContext:    contextWithContextLogger,
		log:             packageLevelLog,
		wantContextLogs: 1,
	}, {
		name:            "LogWith uses the context logger",
		buildContext:    contextWithContextLogger,
		log:             packageLevelLogWith,
		wantContextLogs: 1,
	}, {
		name:            "Log falls back to the package-level logger",
		buildContext:    contextWithoutLogger,
		log:             packageLevelLog,
		wantDefaultLogs: 1,
	}, {
		name:            "LogWith falls back to the package-level logger",
		buildContext:    contextWithoutLogger,
		log:             packageLevelLogWith,
		wantDefaultLogs: 1,
	}, {
		name: "a nil logger keeps the package-level logger",
		buildContext: func(_, _ *seclog.Logger) context.Context {
			return seclog.ContextWithLogger(context.Background(), nil)
		},
		log:             packageLevelLog,
		wantDefaultLogs: 1,
	}, {
		name: "the last logger of the context wins",
		buildContext: func(contextLogger, defaultLogger *seclog.Logger) context.Context {
			ctx := seclog.ContextWithLogger(context.Background(), defaultLogger)
			return seclog.ContextWithLogger(ctx, contextLogger)
		},
		log:             packageLevelLog,
		wantContextLogs: 1,
	}, {
		name: "a nil context is treated as background",
		log: func(_ context.Context, _ *seclog.Logger) {
			seclog.Log(nil, principalEvent())
		},
		buildContext:    contextWithContextLogger,
		wantDefaultLogs: 1,
	}, {
		// A logger emits with its own configuration, so that a component
		// holding one is not silently redirected by its caller.
		name:         "the methods of a logger ignore the context logger",
		buildContext: contextWithContextLogger,
		log: func(ctx context.Context, defaultLogger *seclog.Logger) {
			defaultLogger.Log(ctx, principalEvent())
		},
		wantDefaultLogs: 1,
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			contextHandler := newRecordingHandler()
			packageHandler := newRecordingHandler()
			contextLogger := seclog.NewLogger("my-context-app", seclog.WithHandler(contextHandler))
			packageLogger := seclog.NewLogger(testAppID, seclog.WithHandler(packageHandler))
			withDefaultLogger(c, packageLogger)

			test.log(test.buildContext(contextLogger, packageLogger), packageLogger)

			c.Assert(contextHandler.Records(), qt.HasLen, test.wantContextLogs)
			c.Assert(packageHandler.Records(), qt.HasLen, test.wantDefaultLogs)
		})
	}
}

// TestContextLoggerKeepsTheContextValues asserts that the logger of the
// context resolves the principal and the fields of that same context, so that
// nothing is lost by not passing the logger explicitly.
func TestContextLoggerKeepsTheContextValues(t *testing.T) {
	c := qt.New(t)

	handler := newRecordingHandler()
	withDefaultLogger(c, seclog.NewLogger("my-package-app", seclog.WithHandler(newRecordingHandler())))

	ctx := seclog.ContextWithLogger(context.Background(),
		seclog.NewLogger("my-context-app", seclog.WithHandler(handler)))
	ctx = seclog.ContextWithPrincipal(ctx, &seclog.Principal{Account: "ctx"})
	ctx = seclog.ContextWithFields(ctx, seclog.Fields{TraceID: "t"})

	seclog.Log(ctx, principalEvent())

	records := handler.Records()
	c.Assert(records, qt.HasLen, 1)
	c.Assert(attrs(records[0])["appid"], qt.Equals, "my-context-app")
	c.Assert(attrs(records[0])["event"], qt.Equals, "mytype:<account:ctx>")
	c.Assert(attrs(records[0])["trace_id"], qt.Equals, "t")
}

func TestConcurrentSetupAndLog(t *testing.T) {
	c := qt.New(t)

	handler := newRecordingHandler()
	withDefaultLogger(c, seclog.NewLogger(testAppID, seclog.WithHandler(handler)))

	const goroutines = 8
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(2 * goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				seclog.Setup(testAppID, seclog.WithHandler(handler))
			}
		}()
		go func() {
			defer wg.Done()
			ctx := seclog.ContextWithFields(context.Background(), seclog.Fields{TraceID: "t"})
			for j := 0; j < iterations; j++ {
				seclog.Log(ctx, principalEvent())
			}
		}()
	}
	wg.Wait()

	c.Assert(handler.Records(), qt.HasLen, goroutines*iterations)
}

// principalEvent returns an event rendering the resolved principal as its only
// qualifier, so that principal resolution is observable in the output.
func principalEvent() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		return seclog.Event{
			Name:       "mytype",
			Severity:   seclog.SeverityInfo,
			Qualifiers: []string{ec.Principal.String()},
		}
	}
}

// contextWithContextLogger returns a context carrying the given context
// logger, the usual setup of the context logger tests.
func contextWithContextLogger(contextLogger, _ *seclog.Logger) context.Context {
	return seclog.ContextWithLogger(context.Background(), contextLogger)
}

// contextWithoutLogger returns a context carrying no logger.
func contextWithoutLogger(_, _ *seclog.Logger) context.Context {
	return context.Background()
}

// packageLevelLog emits one event with the package-level Log.
func packageLevelLog(ctx context.Context, _ *seclog.Logger) {
	seclog.Log(ctx, principalEvent())
}

// packageLevelLogWith emits one event with the package-level LogWith.
func packageLevelLogWith(ctx context.Context, _ *seclog.Logger) {
	seclog.LogWith(ctx, &seclog.Principal{Account: "user1"},
		seclog.Fields{TraceID: "trace-1"}, principalEvent())
}

// assertHandler asserts the logger's handler, skipping the assertion when the
// test does not expect a specific one.
func assertHandler(c *qt.C, logger *seclog.Logger, want slog.Handler) {
	c.Helper()

	if want == nil {
		return
	}
	c.Assert(logger.Handler(), qt.Equals, want)
}

func BenchmarkLog(b *testing.B) {
	principal := &seclog.Principal{Account: "username1"}
	loggerFields := seclog.Fields{Region: "us-east-1", HostName: "host-1"}
	contextFields := seclog.Fields{TraceID: "trace-1", RequestURI: "/login"}

	benchmarks := []struct {
		name    string
		fields  seclog.Fields
		context func() context.Context
		events  int
	}{{
		name:    "no fields",
		context: context.Background,
		events:  1,
	}, {
		name:    "default fields",
		fields:  loggerFields,
		context: context.Background,
		events:  1,
	}, {
		name:   "contextual overrides",
		fields: loggerFields,
		context: func() context.Context {
			ctx := seclog.ContextWithPrincipal(context.Background(), principal)
			return seclog.ContextWithFields(ctx, contextFields)
		},
		events: 1,
	}, {
		name:   "multiple events",
		fields: loggerFields,
		context: func() context.Context {
			ctx := seclog.ContextWithPrincipal(context.Background(), principal)
			return seclog.ContextWithFields(ctx, contextFields)
		},
		events: 3,
	}}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			logger := seclog.NewLogger(
				testAppID,
				seclog.WithFields(benchmark.fields),
				seclog.WithHandler(slog.NewJSONHandler(discard{}, nil)),
			)
			ctx := benchmark.context()
			events := make([]seclog.EventFunc, benchmark.events)
			for i := range events {
				events[i] = principalEvent()
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				logger.Log(ctx, events...)
			}
		})
	}
}

// discard is an io.Writer dropping everything written to it.
type discard struct{}

func (discard) Write(p []byte) (int, error) {
	return len(p), nil
}
