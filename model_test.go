// Copyright 2026 Canonical Ltd.

package seclog_test

import (
	"context"
	"testing"

	"github.com/canonical/go-seclog"
	qt "github.com/frankban/quicktest"
)

func TestFormatOWASPEvent(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name  string
		event seclog.Event
		want  string
	}{{
		name:  "no qualifiers omits the separator",
		event: seclog.Event{Name: "sometype"},
		want:  "sometype",
	}, {
		name:  "one qualifier",
		event: seclog.Event{Name: "authn_login_success", Qualifiers: []string{"<account:a>"}},
		want:  "authn_login_success:<account:a>",
	}, {
		name:  "several qualifiers",
		event: seclog.Event{Name: "user_created", Qualifiers: []string{"unknown", "u1", "a,b"}},
		want:  "user_created:unknown,u1,a,b",
	}, {
		name:  "a single empty qualifier still renders the separator",
		event: seclog.Event{Name: "sys_crash", Qualifiers: []string{""}},
		want:  "sys_crash:",
	}, {
		name:  "trailing empty qualifier is preserved",
		event: seclog.Event{Name: "authn_token_created", Qualifiers: []string{"unknown", ""}},
		want:  "authn_token_created:unknown,",
	}, {
		name:  "empty name with qualifiers",
		event: seclog.Event{Qualifiers: []string{"unknown"}},
		want:  ":unknown",
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			c.Assert(seclog.FormatOWASPEvent(test.event), qt.Equals, test.want)
		})
	}
}

func TestOWASPModel(t *testing.T) {
	c := qt.New(t)

	c.Assert(seclog.NewOWASPModel().Name(), qt.Equals, "owasp")

	tests := []struct {
		name      string
		event     seclog.Event
		principal *seclog.Principal
		fields    seclog.Fields
		want      map[string]any
	}{{
		name:  "required fields only",
		event: seclog.Event{Name: "sometype", Severity: seclog.SeverityInfo},
		want:  owaspRecord("sometype", "", "INFO", nil),
	}, {
		name: "description and qualifiers",
		event: seclog.Event{
			Name:        "mytype",
			Severity:    seclog.SeverityCritical,
			Qualifiers:  []string{"a", "b"},
			Description: "mydescription",
		},
		want: owaspRecord("mytype:a,b", "mydescription", "CRITICAL", nil),
	}, {
		name: "the structured principal and the reason are ignored",
		event: seclog.Event{
			Name:     "authn_login_lock",
			Severity: seclog.SeverityWarn,
			Reason:   "maxretries",
		},
		principal: &seclog.Principal{Account: "username1"},
		want:      owaspRecord("authn_login_lock", "", "WARN", nil),
	}, {
		name:   "zero-valued fields are omitted",
		event:  seclog.Event{Name: "mytype", Severity: seclog.SeverityInfo},
		fields: seclog.Fields{OWASPPort: 0, HTTPStatusCode: 0, TraceID: ""},
		want:   owaspRecord("mytype", "", "INFO", nil),
	}, {
		name:   "every supported field",
		event:  seclog.Event{Name: "mytype", Severity: seclog.SeverityInfo},
		fields: fullFields(),
		want: owaspRecord("mytype", "", "INFO", map[string]any{
			"trace_id":         "trace-1",
			"span_id":          "span-1",
			"transaction_id":   "transaction-1",
			"useragent":        "agent-1",
			"source_ip":        "192.0.2.1",
			"source_port":      float64(1111),
			"destination_port": float64(2222),
			"host_ip":          "192.0.2.2",
			"hostname":         "host-1",
			"protocol":         "https",
			"port":             float64(3333),
			"request_uri":      "/login",
			"request_method":   "POST",
			"region":           "us-east-1",
			"geo":              "geo-1",
			"service_version":  "1.2.3",
			"http_status_code": float64(200),
		}),
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			logger, decode := jsonLogger(seclog.NewOWASPModel(), testAppID)
			logger.LogWith(context.Background(), test.principal, test.fields, testEvent(test.event))

			assertRecords(c, decode, []map[string]any{test.want})
		})
	}
}

func TestECSModel(t *testing.T) {
	c := qt.New(t)

	c.Assert(seclog.NewECSModel().Name(), qt.Equals, "ecs")

	baseEvent := seclog.Event{
		Name:        "authn_login_success",
		Kind:        seclog.KindEvent,
		Action:      "user-login",
		Categories:  []string{"authentication"},
		Types:       []string{"access"},
		Outcome:     seclog.OutcomeSuccess,
		Severity:    seclog.SeverityInfo,
		Qualifiers:  []string{"<account:username1>"},
		Description: "User <account:username1> login successfully",
	}

	tests := []struct {
		name      string
		event     seclog.Event
		principal *seclog.Principal
		fields    seclog.Fields
		want      map[string]any
	}{{
		name:  "event metadata without a principal",
		event: baseEvent,
		want: map[string]any{
			"message":        "User <account:username1> login successfully",
			"service.name":   testAppID,
			"event.kind":     "event",
			"event.code":     "authn_login_success",
			"event.action":   "user-login",
			"event.category": []any{"authentication"},
			"event.type":     []any{"access"},
			"event.outcome":  "success",
			"event.severity": float64(1),
			"log.level":      "INFO",
		},
	}, {
		name: "critical severity and reason",
		event: seclog.Event{
			Name:     "sys_crash",
			Kind:     seclog.KindEvent,
			Severity: seclog.SeverityCritical,
			Outcome:  seclog.OutcomeFailure,
			Reason:   "out-of-memory",
		},
		want: map[string]any{
			"message":        "",
			"service.name":   testAppID,
			"event.kind":     "event",
			"event.code":     "sys_crash",
			"event.outcome":  "failure",
			"event.reason":   "out-of-memory",
			"event.severity": float64(3),
			"log.level":      "CRITICAL",
		},
	}, {
		name:      "an empty principal is omitted",
		event:     baseEvent,
		principal: &seclog.Principal{},
		want: map[string]any{
			"message":        "User <account:username1> login successfully",
			"service.name":   testAppID,
			"event.kind":     "event",
			"event.code":     "authn_login_success",
			"event.action":   "user-login",
			"event.category": []any{"authentication"},
			"event.type":     []any{"access"},
			"event.outcome":  "success",
			"event.severity": float64(1),
			"log.level":      "INFO",
		},
	}, {
		name:  "an account maps to user.name",
		event: baseEvent,
		principal: &seclog.Principal{
			Account: "username1",
			Email:   "user@example.com",
			Name:    "John Doe",
		},
		want: map[string]any{
			"message":        "User <account:username1> login successfully",
			"service.name":   testAppID,
			"event.kind":     "event",
			"event.code":     "authn_login_success",
			"event.action":   "user-login",
			"event.category": []any{"authentication"},
			"event.type":     []any{"access"},
			"event.outcome":  "success",
			"event.severity": float64(1),
			"log.level":      "INFO",
			"user.name":      "username1",
			"user.email":     "user@example.com",
			"user.full_name": "John Doe",
		},
	}, {
		name:      "a lone service account maps to user.name",
		event:     baseEvent,
		principal: &seclog.Principal{ServiceAccount: "service1"},
		want: map[string]any{
			"message":        "User <account:username1> login successfully",
			"service.name":   testAppID,
			"event.kind":     "event",
			"event.code":     "authn_login_success",
			"event.action":   "user-login",
			"event.category": []any{"authentication"},
			"event.type":     []any{"access"},
			"event.outcome":  "success",
			"event.severity": float64(1),
			"log.level":      "INFO",
			"user.name":      "service1",
		},
	}, {
		name:      "a service account acting for an account is the effective user",
		event:     baseEvent,
		principal: &seclog.Principal{Account: "username1", ServiceAccount: "service1"},
		want: map[string]any{
			"message":             "User <account:username1> login successfully",
			"service.name":        testAppID,
			"event.kind":          "event",
			"event.code":          "authn_login_success",
			"event.action":        "user-login",
			"event.category":      []any{"authentication"},
			"event.type":          []any{"access"},
			"event.outcome":       "success",
			"event.severity":      float64(1),
			"log.level":           "INFO",
			"user.name":           "username1",
			"user.effective.name": "service1",
		},
	}, {
		name: "the OWASP-only fields are omitted and the others are mapped",
		event: seclog.Event{
			Name:     "mytype",
			Kind:     seclog.KindEvent,
			Severity: seclog.SeverityWarn,
		},
		fields: fullFields(),
		want: map[string]any{
			"message":                          "",
			"service.name":                     testAppID,
			"service.version":                  "1.2.3",
			"event.kind":                       "event",
			"event.code":                       "mytype",
			"event.severity":                   float64(2),
			"log.level":                        "WARN",
			"trace.id":                         "trace-1",
			"span.id":                          "span-1",
			"transaction.id":                   "transaction-1",
			"user_agent.original":              "agent-1",
			"source.ip":                        "192.0.2.1",
			"source.port":                      float64(1111),
			"destination.port":                 float64(2222),
			"host.ip":                          "192.0.2.2",
			"host.hostname":                    "host-1",
			"network.protocol":                 "https",
			"url.original":                     "/login",
			"http.request.method":              "POST",
			"http.response.status_code":        float64(200),
			"cloud.region":                     "us-east-1",
			"source.geo.city_name":             "London",
			"source.geo.country_iso_code":      "GB",
			"source.geo.country_name":          "United Kingdom",
			"source.geo.continent_code":        "EU",
			"source.geo.continent_name":        "Europe",
			"source.geo.region_name":           "England",
			"source.geo.region_iso_code":       "GB-ENG",
			"source.geo.location":              map[string]any{"lat": 51.5, "lon": -0.1},
			"destination.geo.city_name":        "Lisbon",
			"destination.geo.country_iso_code": "PT",
			"destination.geo.country_name":     "Portugal",
			"destination.geo.continent_code":   "EU",
			"destination.geo.continent_name":   "Europe",
			"destination.geo.region_name":      "Lisboa",
			"destination.geo.region_iso_code":  "PT-11",
			"destination.geo.location":         map[string]any{"lat": 38.7, "lon": -9.1},
		},
	}, {
		name: "a zero coordinate is part of the location",
		event: seclog.Event{
			Name:     "mytype",
			Kind:     seclog.KindEvent,
			Severity: seclog.SeverityInfo,
		},
		fields: seclog.Fields{SourceGeo: seclog.GeoFields{
			CityName: "London",
			Location: &seclog.GeoPoint{Latitude: 51.5},
		}},
		want: map[string]any{
			"message":              "",
			"service.name":         testAppID,
			"event.kind":           "event",
			"event.code":           "mytype",
			"event.severity":       float64(1),
			"log.level":            "INFO",
			"source.geo.city_name": "London",
			"source.geo.location":  map[string]any{"lat": 51.5, "lon": float64(0)},
		},
	}, {
		name: "a nil location is omitted",
		event: seclog.Event{
			Name:     "mytype",
			Kind:     seclog.KindEvent,
			Severity: seclog.SeverityInfo,
		},
		fields: seclog.Fields{SourceGeo: seclog.GeoFields{
			CityName: "London",
		}},
		want: map[string]any{
			"message":              "",
			"service.name":         testAppID,
			"event.kind":           "event",
			"event.code":           "mytype",
			"event.severity":       float64(1),
			"log.level":            "INFO",
			"source.geo.city_name": "London",
		},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			logger, decode := jsonLogger(seclog.NewECSModel(), testAppID)
			logger.LogWith(context.Background(), test.principal, test.fields, testEvent(test.event))

			assertRecords(c, decode, []map[string]any{test.want})
		})
	}
}
