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

// ecsTimeLayout is the timestamp layout used for the ECS @timestamp field.
const ecsTimeLayout = "2006-01-02T15:04:05.000Z07:00"

// ECS numeric severities. ECS defines event.severity as a source-specific
// numeric value.
const (
	ecsSeverityInfo     = 1
	ecsSeverityWarn     = 2
	ecsSeverityCritical = 3
)

// NewECSModel returns the model emitting the Elastic Common Schema
// representation of an event.
//
// It emits, when applicable:
//
//   - service.name from the configured application ID, and service.version;
//   - event.kind, event.code, event.action, event.category, event.type,
//     event.outcome, event.reason and the numeric event.severity;
//   - log.level as the textual severity, so the output stays readable
//     without knowing the numeric convention;
//   - user.* from the principal, omitted entirely when no principal is
//     present;
//   - the mapped non-zero members of Fields.
//
// The timestamp is emitted by the handler as @timestamp, and the event
// description as message. ECS does not define an appid field, so the
// application identity is emitted as service.name only.
//
// The OWASP-only members OWASPPort and OWASPGeo are never emitted; use
// SourcePort, DestinationPort, SourceGeo and DestinationGeo instead.
//
// The returned model is stateless, so it can be shared by any number of
// loggers.
func NewECSModel() Model {
	return ecsModel{}
}

type ecsModel struct{}

// Name implements Model.
func (ecsModel) Name() string {
	return "ecs"
}

// NewECSHandler returns the handler used by the ECS model, writing JSON to w
// with the ECS @timestamp and message keys.
//
// Use it, or WithWriter, when the records must keep the ECS envelope and the
// handler has to be composed, for example with buffering or fan-out.
//
//	logger := seclog.NewLogger("my-app",
//		seclog.WithModel(seclog.NewECSModel()),
//		seclog.WithHandler(myMiddleware(seclog.NewECSHandler(file))),
//	)
func NewECSHandler(w io.Writer) slog.Handler {
	return ecsModel{}.NewHandler(w)
}

// NewHandler implements HandlerProvider. The returned handler writes JSON to w
// using the ECS @timestamp and message keys. The slog level attribute is
// dropped, because the model emits the textual severity as log.level.
func (ecsModel) NewHandler(w io.Writer) slog.Handler {
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
				return slog.String("@timestamp", a.Value.Time().Format(ecsTimeLayout))
			case slog.MessageKey:
				return slog.String("message", a.Value.String())
			case slog.LevelKey:
				if _, isLevel := a.Value.Any().(slog.Level); !isLevel {
					return a
				}
				return slog.Attr{}
			}
			return a
		},
	})
}

// AppendAttrs implements Model.
func (ecsModel) AppendAttrs(
	dst []slog.Attr,
	appID string,
	event Event,
	principal *Principal,
	fields Fields,
) []slog.Attr {
	dst = appendNonEmptyString(dst, "service.name", appID)
	dst = appendNonEmptyString(dst, "service.version", fields.ServiceVersion)

	dst = appendNonEmptyString(dst, "event.kind", event.Kind)
	// event.code carries the stable OWASP identifier, which has no
	// equivalent in the ECS action and category vocabularies.
	dst = appendNonEmptyString(dst, "event.code", event.Name)
	dst = appendNonEmptyString(dst, "event.action", event.Action)
	dst = appendNonEmptyStrings(dst, "event.category", event.Categories)
	dst = appendNonEmptyStrings(dst, "event.type", event.Types)
	dst = appendNonEmptyString(dst, "event.outcome", string(event.Outcome))
	dst = appendNonEmptyString(dst, "event.reason", event.Reason)
	if event.Severity != "" {
		dst = append(dst,
			slog.Int("event.severity", ecsSeverity(event.Severity)),
			slog.String("log.level", string(event.Severity)),
		)
	}

	dst = appendECSPrincipal(dst, principal)
	return appendECSFields(dst, fields)
}

// ecsSeverity maps the package's textual severity to its numeric ECS
// convention. An unrecognized severity maps to the informational value.
func ecsSeverity(severity Severity) int {
	switch severity {
	case SeverityWarn:
		return ecsSeverityWarn
	case SeverityCritical:
		return ecsSeverityCritical
	default:
		return ecsSeverityInfo
	}
}

// appendECSPrincipal appends the user.* attributes for principal. Nothing is
// appended when the principal carries no information, because "unknown" is an
// OWASP rendering convention and not a real user name.
func appendECSPrincipal(dst []slog.Attr, principal *Principal) []slog.Attr {
	if principal.isEmpty() {
		return dst
	}

	// user.effective.name is the ECS location for the identity whose
	// privileges are actually in use.
	if principal.Account != "" {
		dst = append(dst, slog.String("user.name", principal.Account))
		dst = appendNonEmptyString(dst, "user.effective.name", principal.ServiceAccount)
	} else {
		dst = appendNonEmptyString(dst, "user.name", principal.ServiceAccount)
	}
	dst = appendNonEmptyString(dst, "user.email", principal.Email)
	dst = appendNonEmptyString(dst, "user.full_name", principal.Name)
	return dst
}

// appendECSFields appends the non-zero members of fields that the ECS schema
// supports.
func appendECSFields(dst []slog.Attr, fields Fields) []slog.Attr {
	dst = appendNonEmptyString(dst, "trace.id", fields.TraceID)
	dst = appendNonEmptyString(dst, "span.id", fields.SpanID)
	dst = appendNonEmptyString(dst, "transaction.id", fields.TransactionID)
	dst = appendNonEmptyString(dst, "user_agent.original", fields.UserAgent)
	dst = appendNonEmptyString(dst, "source.ip", fields.SourceIP)
	dst = appendNonZeroInt(dst, "source.port", fields.SourcePort)
	dst = appendNonZeroInt(dst, "destination.port", fields.DestinationPort)
	dst = appendNonEmptyString(dst, "host.ip", fields.HostIP)
	dst = appendNonEmptyString(dst, "host.hostname", fields.HostName)
	dst = appendNonEmptyString(dst, "network.protocol", fields.Protocol)
	dst = appendNonEmptyString(dst, "url.original", fields.RequestURI)
	dst = appendNonEmptyString(dst, "http.request.method", fields.RequestMethod)
	dst = appendNonZeroInt(dst, "http.response.status_code", fields.HTTPStatusCode)
	dst = appendNonEmptyString(dst, "cloud.region", fields.Region)
	dst = appendECSGeo(dst, "source.geo.", fields.SourceGeo)
	dst = appendECSGeo(dst, "destination.geo.", fields.DestinationGeo)
	return dst
}

// appendECSGeo appends the non-zero members of geo under the given ECS prefix.
// The location is emitted whenever a point is supplied, as zero is a valid
// latitude and a valid longitude.
func appendECSGeo(dst []slog.Attr, prefix string, geo GeoFields) []slog.Attr {
	dst = appendNonEmptyString(dst, prefix+"city_name", geo.CityName)
	dst = appendNonEmptyString(dst, prefix+"country_iso_code", geo.CountryISOCode)
	dst = appendNonEmptyString(dst, prefix+"country_name", geo.CountryName)
	dst = appendNonEmptyString(dst, prefix+"continent_code", geo.ContinentCode)
	dst = appendNonEmptyString(dst, prefix+"continent_name", geo.ContinentName)
	dst = appendNonEmptyString(dst, prefix+"region_name", geo.RegionName)
	dst = appendNonEmptyString(dst, prefix+"region_iso_code", geo.RegionISOCode)
	if geo.Location != nil {
		dst = append(dst, slog.Group(prefix+"location",
			slog.Float64("lat", geo.Location.Latitude),
			slog.Float64("lon", geo.Location.Longitude),
		))
	}
	return dst
}

// appendNonEmptyStrings appends a string slice attribute only when values has
// at least one element.
func appendNonEmptyStrings(dst []slog.Attr, key string, values []string) []slog.Attr {
	if len(values) == 0 {
		return dst
	}
	return append(dst, slog.Any(key, values))
}
