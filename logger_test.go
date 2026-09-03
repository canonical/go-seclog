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
