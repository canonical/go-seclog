// Copyright 2026 Canonical Ltd.

package seclog

import (
	"io"
	"log/slog"
	"strings"
)

// owaspTimeLayout is the timestamp layout used by the OWASP profile.
const owaspTimeLayout = "2006-01-02T15:04:05-07:00"

// NewOWASPModel returns the default model. It follows the OWASP Logging Cheat
// Sheet recommendations.
//
// It emits:
//
//   - appid: the configured application ID;
//   - event: the event name, followed by ":" and the comma-separated
//     qualifiers when the event has any;
//   - type: always "security";
//   - severity: the textual security severity, INFO, WARN or CRITICAL;
//   - the supported non-zero members of Fields.
//
// The timestamp is emitted by the handler as datetime, and the event
// description as description. The structured Principal and Event.Reason are
// ignored, because the OWASP representation of both is already part of the
// event qualifiers.
//
// The field names are this package's contract; OWASP itself does not mandate a
// fixed JSON schema. The returned model is stateless, so it can be shared by
// any number of loggers.
func NewOWASPModel() Model {
	return owaspModel{}
}

type owaspModel struct{}

// Name implements Model.
func (owaspModel) Name() string {
	return "owasp"
}

// NewOWASPHandler returns the handler used by the OWASP model, writing JSON to
// w with the OWASP datetime and description keys.
//
// Use it, or WithWriter, when the records must keep the OWASP envelope and the
// handler has to be composed, for example with buffering or fan-out.
//
//	logger := seclog.NewLogger("my-app",
//		seclog.WithHandler(myMiddleware(seclog.NewOWASPHandler(file))),
//	)
func NewOWASPHandler(w io.Writer) slog.Handler {
	return owaspModel{}.NewHandler(w)
}

// NewHandler implements HandlerProvider. The returned handler writes JSON to w
// using the OWASP datetime and description keys.
func (owaspModel) NewHandler(w io.Writer) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) > 0 {
				return a
			}
			switch a.Key {
			case slog.TimeKey:
				// The handler may be composed with others, so a "time"
				// attribute is not necessarily the record timestamp;
				// anything else is passed through unchanged.
				if a.Value.Kind() != slog.KindTime {
					return a
				}
				return slog.String("datetime", a.Value.Time().Format(owaspTimeLayout))
			case slog.MessageKey:
				return slog.String("description", a.Value.String())
			}
			return a
		},
	})
}

// AppendAttrs implements Model.
func (owaspModel) AppendAttrs(
	dst []slog.Attr,
	appID string,
	event Event,
	_ *Principal,
	fields Fields,
) []slog.Attr {
	dst = append(dst,
		slog.String("appid", appID),
		slog.String("event", formatOWASPEvent(event)),
		slog.String("type", TypeSecurity),
		slog.String("severity", string(event.Severity)),
	)
	return appendOWASPFields(dst, fields)
}

// appendOWASPFields appends the non-zero members of fields that the OWASP
// profile supports. SourceGeo and DestinationGeo are ECS-only; OWASPGeo is the
// OWASP location field.
func appendOWASPFields(dst []slog.Attr, fields Fields) []slog.Attr {
	dst = appendNonEmptyString(dst, "trace_id", fields.TraceID)
	dst = appendNonEmptyString(dst, "span_id", fields.SpanID)
	dst = appendNonEmptyString(dst, "transaction_id", fields.TransactionID)
	dst = appendNonEmptyString(dst, "useragent", fields.UserAgent)
	dst = appendNonEmptyString(dst, "source_ip", fields.SourceIP)
	dst = appendNonZeroInt(dst, "source_port", fields.SourcePort)
	dst = appendNonZeroInt(dst, "destination_port", fields.DestinationPort)
	dst = appendNonEmptyString(dst, "host_ip", fields.HostIP)
	dst = appendNonEmptyString(dst, "hostname", fields.HostName)
	dst = appendNonEmptyString(dst, "protocol", fields.Protocol)
	dst = appendNonZeroInt(dst, "port", fields.OWASPPort)
	dst = appendNonEmptyString(dst, "request_uri", fields.RequestURI)
	dst = appendNonEmptyString(dst, "request_method", fields.RequestMethod)
	dst = appendNonEmptyString(dst, "region", fields.Region)
	dst = appendNonEmptyString(dst, "geo", fields.OWASPGeo)
	dst = appendNonEmptyString(dst, "service_version", fields.ServiceVersion)
	dst = appendNonZeroInt(dst, "http_status_code", fields.HTTPStatusCode)
	return dst
}

// formatOWASPEvent renders the OWASP event value: the event name, followed by
// a colon and the comma-separated qualifiers.
//
// The colon is appended only when at least one qualifier exists, and empty
// qualifiers are still rendered, so "authn_token_created:unknown," keeps its
// empty trailing qualifier.
func formatOWASPEvent(event Event) string {
	if len(event.Qualifiers) == 0 {
		return event.Name
	}

	size := len(event.Name) + len(event.Qualifiers)
	for _, qualifier := range event.Qualifiers {
		size += len(qualifier)
	}

	var builder strings.Builder
	builder.Grow(size)
	builder.WriteString(event.Name)
	builder.WriteByte(':')
	for i, qualifier := range event.Qualifiers {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(qualifier)
	}
	return builder.String()
}

// appendNonEmptyString appends a string attribute only when value is set.
func appendNonEmptyString(dst []slog.Attr, key, value string) []slog.Attr {
	if value == "" {
		return dst
	}
	return append(dst, slog.String(key, value))
}

// appendNonZeroInt appends an integer attribute only when value is set.
func appendNonZeroInt(dst []slog.Attr, key string, value int) []slog.Attr {
	if value == 0 {
		return dst
	}
	return append(dst, slog.Int(key, value))
}
