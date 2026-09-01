// Copyright 2026 Canonical Ltd.

package seclog_test

import (
	"context"
	"testing"

	"github.com/canonical/go-seclog"
	qt "github.com/frankban/quicktest"
)

func TestFieldsMerge(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		name     string
		base     seclog.Fields
		override seclog.Fields
		want     seclog.Fields
	}{{
		name:     "empty override keeps the base",
		base:     seclog.Fields{UserAgent: "a", SourceIP: "b"},
		override: seclog.Fields{},
		want:     seclog.Fields{UserAgent: "a", SourceIP: "b"},
	}, {
		name:     "empty base takes the override",
		base:     seclog.Fields{},
		override: seclog.Fields{HostIP: "c", HostName: "d"},
		want:     seclog.Fields{HostIP: "c", HostName: "d"},
	}, {
		name:     "disjoint fields are combined",
		base:     seclog.Fields{UserAgent: "a", SourceIP: "b"},
		override: seclog.Fields{HostIP: "c", HostName: "d"},
		want:     seclog.Fields{UserAgent: "a", SourceIP: "b", HostIP: "c", HostName: "d"},
	}, {
		name:     "non-zero override replaces the base",
		base:     seclog.Fields{UserAgent: "a", SourceIP: "b"},
		override: seclog.Fields{UserAgent: "override"},
		want:     seclog.Fields{UserAgent: "override", SourceIP: "b"},
	}, {
		name:     "zero numeric override keeps the base",
		base:     seclog.Fields{OWASPPort: 443, HTTPStatusCode: 200},
		override: seclog.Fields{OWASPPort: 0, HTTPStatusCode: 500},
		want:     seclog.Fields{OWASPPort: 443, HTTPStatusCode: 500},
	}, {
		name:     "every member can be overridden",
		base:     fullFields(),
		override: otherFullFields(),
		want:     otherFullFields(),
	}, {
		name: "geo members are merged individually",
		base: seclog.Fields{SourceGeo: seclog.GeoFields{
			CityName:    "London",
			CountryName: "United Kingdom",
		}},
		override: seclog.Fields{SourceGeo: seclog.GeoFields{
			CityName: "Lisbon",
			Location: &seclog.GeoPoint{Latitude: 38.7, Longitude: -9.1},
		}},
		want: seclog.Fields{SourceGeo: seclog.GeoFields{
			CityName:    "Lisbon",
			CountryName: "United Kingdom",
			Location:    &seclog.GeoPoint{Latitude: 38.7, Longitude: -9.1},
		}},
	}, {
		name: "a nil location override keeps the base location",
		base: seclog.Fields{SourceGeo: seclog.GeoFields{
			Location: &seclog.GeoPoint{Latitude: 51.5, Longitude: -0.1},
		}},
		override: seclog.Fields{SourceGeo: seclog.GeoFields{CityName: "Lisbon"}},
		want: seclog.Fields{SourceGeo: seclog.GeoFields{
			CityName: "Lisbon",
			Location: &seclog.GeoPoint{Latitude: 51.5, Longitude: -0.1},
		}},
	}, {
		name: "a zero location override replaces the base location",
		base: seclog.Fields{SourceGeo: seclog.GeoFields{
			Location: &seclog.GeoPoint{Latitude: 51.5, Longitude: -0.1},
		}},
		override: seclog.Fields{SourceGeo: seclog.GeoFields{
			Location: &seclog.GeoPoint{},
		}},
		want: seclog.Fields{SourceGeo: seclog.GeoFields{
			Location: &seclog.GeoPoint{},
		}},
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			base := test.base
			got := base.Merge(test.override)

			c.Assert(got, qt.DeepEquals, test.want)
			c.Assert(base, qt.DeepEquals, test.base, qt.Commentf("merge must not mutate the receiver"))
		})
	}
}

func TestContextWithFields(t *testing.T) {
	c := qt.New(t)

	fields1 := seclog.Fields{UserAgent: "a", SourceIP: "b"}
	fields2 := seclog.Fields{HostIP: "c", HostName: "d"}

	tests := []struct {
		name      string
		nilParent bool
		fields    []seclog.Fields
		want      *seclog.Fields
	}{{
		name:   "without fields",
		fields: nil,
		want:   nil,
	}, {
		name:   "zero fields are not stored",
		fields: []seclog.Fields{{}},
		want:   nil,
	}, {
		name:   "setting fields once",
		fields: []seclog.Fields{fields1},
		want:   &fields1,
	}, {
		name:   "setting fields twice merges them",
		fields: []seclog.Fields{fields1, fields2},
		want:   &seclog.Fields{UserAgent: "a", SourceIP: "b", HostIP: "c", HostName: "d"},
	}, {
		name: "setting fields twice overrides existing non-zero fields",
		fields: []seclog.Fields{
			{UserAgent: "a", SourceIP: "b"},
			{UserAgent: "override"},
		},
		want: &seclog.Fields{UserAgent: "override", SourceIP: "b"},
	}, {
		name:      "a nil parent is treated as background",
		nilParent: true,
		fields:    []seclog.Fields{fields1},
		want:      &fields1,
	}, {
		name:      "a nil parent with zero fields is treated as background",
		nilParent: true,
		fields:    []seclog.Fields{{}},
		want:      nil,
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			ctx := context.Background()
			if test.nilParent {
				ctx = nil
			}
			for _, fields := range test.fields {
				ctx = seclog.ContextWithFields(ctx, fields)
			}

			// The helper never returns a nil context, so a caller that
			// builds its values before logging cannot be handed one.
			c.Assert(ctx, qt.IsNotNil)
			c.Assert(seclog.FieldsFromContext(ctx), qt.DeepEquals, test.want)
		})
	}
}

func TestContextWithFieldsPreservesParent(t *testing.T) {
	c := qt.New(t)

	parent := seclog.ContextWithFields(context.Background(), seclog.Fields{TraceID: "parent"})
	child := seclog.ContextWithFields(parent, seclog.Fields{TraceID: "child"})

	c.Assert(seclog.FieldsFromContext(parent), qt.DeepEquals, &seclog.Fields{TraceID: "parent"})
	c.Assert(seclog.FieldsFromContext(child), qt.DeepEquals, &seclog.Fields{TraceID: "child"})
}

// fullFields returns a Fields value with every member populated.
func fullFields() seclog.Fields {
	return seclog.Fields{
		TraceID:         "trace-1",
		SpanID:          "span-1",
		TransactionID:   "transaction-1",
		UserAgent:       "agent-1",
		SourceIP:        "192.0.2.1",
		SourcePort:      1111,
		DestinationPort: 2222,
		HostIP:          "192.0.2.2",
		HostName:        "host-1",
		Protocol:        "https",
		OWASPPort:       3333,
		RequestURI:      "/login",
		RequestMethod:   "POST",
		Region:          "us-east-1",
		OWASPGeo:        "geo-1",
		SourceGeo: seclog.GeoFields{
			CityName:       "London",
			CountryISOCode: "GB",
			CountryName:    "United Kingdom",
			ContinentCode:  "EU",
			ContinentName:  "Europe",
			RegionName:     "England",
			RegionISOCode:  "GB-ENG",
			Location:       &seclog.GeoPoint{Latitude: 51.5, Longitude: -0.1},
		},
		DestinationGeo: seclog.GeoFields{
			CityName:       "Lisbon",
			CountryISOCode: "PT",
			CountryName:    "Portugal",
			ContinentCode:  "EU",
			ContinentName:  "Europe",
			RegionName:     "Lisboa",
			RegionISOCode:  "PT-11",
			Location:       &seclog.GeoPoint{Latitude: 38.7, Longitude: -9.1},
		},
		ServiceVersion: "1.2.3",
		HTTPStatusCode: 200,
	}
}

// otherFullFields returns a Fields value with every member populated with a
// value different from fullFields.
func otherFullFields() seclog.Fields {
	return seclog.Fields{
		TraceID:         "trace-2",
		SpanID:          "span-2",
		TransactionID:   "transaction-2",
		UserAgent:       "agent-2",
		SourceIP:        "198.51.100.1",
		SourcePort:      4444,
		DestinationPort: 5555,
		HostIP:          "198.51.100.2",
		HostName:        "host-2",
		Protocol:        "http",
		OWASPPort:       6666,
		RequestURI:      "/logout",
		RequestMethod:   "GET",
		Region:          "eu-west-1",
		OWASPGeo:        "geo-2",
		SourceGeo: seclog.GeoFields{
			CityName:       "Paris",
			CountryISOCode: "FR",
			CountryName:    "France",
			ContinentCode:  "EU",
			ContinentName:  "Europe",
			RegionName:     "Ile-de-France",
			RegionISOCode:  "FR-IDF",
			Location:       &seclog.GeoPoint{Latitude: 48.9, Longitude: 2.4},
		},
		DestinationGeo: seclog.GeoFields{
			CityName:       "Madrid",
			CountryISOCode: "ES",
			CountryName:    "Spain",
			ContinentCode:  "EU",
			ContinentName:  "Europe",
			RegionName:     "Madrid",
			RegionISOCode:  "ES-MD",
			Location:       &seclog.GeoPoint{Latitude: 40.4, Longitude: -3.7},
		},
		ServiceVersion: "4.5.6",
		HTTPStatusCode: 404,
	}
}
