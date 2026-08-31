// Copyright 2026 Canonical Ltd.

package seclog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/canonical/go-seclog"
	qt "github.com/frankban/quicktest"
)

const testAppID = "my-app"

// testEvent returns an event function emitting the given event, so that logger
// tests do not depend on the event subpackage.
func testEvent(event seclog.Event) seclog.EventFunc {
	return func(seclog.EventContext) seclog.Event {
		return event
	}
}

// testEvents converts a list of events into their event functions.
func testEvents(events []seclog.Event) []seclog.EventFunc {
	if events == nil {
		return nil
	}

	eventFuncs := make([]seclog.EventFunc, 0, len(events))
	for _, event := range events {
		eventFuncs = append(eventFuncs, testEvent(event))
	}
	return eventFuncs
}

// jsonLogger returns a logger writing the model's JSON representation into a
// buffer, together with a function decoding the buffered records.
//
// The timestamp keys are removed from the decoded records, as their values are
// not deterministic.
func jsonLogger(model seclog.Model, appID string, options ...seclog.Option) (*seclog.Logger, func() []map[string]any) {
	var buffer bytes.Buffer

	options = append([]seclog.Option{seclog.WithModel(model), seclog.WithWriter(&buffer)}, options...)
	logger := seclog.NewLogger(appID, options...)

	return logger, func() []map[string]any {
		return decodeRecords(buffer.Bytes())
	}
}

// decodeRecords decodes the newline-delimited JSON records in data, dropping
// the nondeterministic timestamp keys.
func decodeRecords(data []byte) []map[string]any {
	var records []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		record := map[string]any{}
		if err := json.Unmarshal(line, &record); err != nil {
			panic(err)
		}
		delete(record, "datetime")
		delete(record, "@timestamp")
		records = append(records, record)
	}
	return records
}

// recordKeys returns the sorted keys of the single JSON record in data, or nil
// when no record was written. Unlike decodeRecords, it keeps the timestamp
// keys, so that tests can assert the complete output envelope.
func recordKeys(data []byte) []string {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}

	record := map[string]any{}
	if err := json.Unmarshal(data, &record); err != nil {
		panic(err)
	}
	return slices.Sorted(maps.Keys(record))
}

// assertRecords asserts that the logger emitted exactly the expected records.
func assertRecords(c *qt.C, decode func() []map[string]any, want []map[string]any) {
	c.Helper()
	c.Assert(decode(), qt.DeepEquals, want)
}

// owaspRecord returns the OWASP record that testAppID emits for an event with
// the given value, description and severity, extended with the given fields.
func owaspRecord(event, description, severity string, fields map[string]any) map[string]any {
	record := map[string]any{
		"level":       "INFO",
		"appid":       testAppID,
		"type":        "security",
		"event":       event,
		"severity":    severity,
		"description": description,
	}
	for key, value := range fields {
		record[key] = value
	}
	return record
}

// recordingHandler is a slog handler capturing the records it receives. It is
// safe for concurrent use, so that concurrency tests can rely on it.
type recordingHandler struct {
	mu       sync.Mutex
	records  []slog.Record
	disabled bool
	err      error
}

// newRecordingHandler returns a handler capturing every record it receives.
func newRecordingHandler() *recordingHandler {
	return &recordingHandler{}
}

// newDisabledHandler returns a handler that reports itself as disabled.
func newDisabledHandler() *recordingHandler {
	return &recordingHandler{disabled: true}
}

// newFailingHandler returns a handler that captures every record it receives
// and then fails with err.
func newFailingHandler(err error) *recordingHandler {
	return &recordingHandler{err: err}
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool {
	return !h.disabled
}

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, record.Clone())
	return h.err
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *recordingHandler) WithGroup(string) slog.Handler {
	return h
}

// Records returns a copy of the captured records.
func (h *recordingHandler) Records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]slog.Record(nil), h.records...)
}

// attrs returns the attributes of a captured record as a map.
func attrs(record slog.Record) map[string]any {
	result := make(map[string]any, record.NumAttrs())
	record.Attrs(func(a slog.Attr) bool {
		result[a.Key] = a.Value.Any()
		return true
	})
	return result
}

// withDefaultLogger replaces the package-level logger for the duration of the
// test, restoring the previous one when the test ends.
func withDefaultLogger(t testing.TB, logger *seclog.Logger) {
	t.Helper()

	previous := seclog.SetDefaultLogger(logger)
	t.Cleanup(func() {
		seclog.SetDefaultLogger(previous)
	})
}
