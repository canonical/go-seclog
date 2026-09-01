// Copyright 2026 Canonical Ltd.

package seclog

import "context"

// Fields is the closed set of contextual values that this package knows how to
// emit. Callers populate the members they have, and the configured Model
// decides the output representation for each one.
//
// A zero-valued member means "not supplied" and is omitted by every model, so
// a caller cannot emit port: 0 or an empty trace identifier.
//
// A few members belong to one vocabulary only: OWASPPort and OWASPGeo are
// emitted by the OWASP model, and SourcePort, DestinationPort, SourceGeo and
// DestinationGeo by the ECS model.
//
// Values can be supplied to a Logger with WithFields, to a context with
// ContextWithFields, or to a single call with LogWith.
type Fields struct {
	// TraceID correlates events belonging to one request or interaction.
	// OWASP: interaction identifier. ECS: trace.id.
	TraceID string

	// SpanID identifies the current operation in a distributed trace.
	// ECS: span.id.
	SpanID string

	// TransactionID identifies the transaction within a trace.
	// ECS: transaction.id.
	TransactionID string

	// UserAgent is the original client user-agent value.
	// OWASP: HTTP User Agent. ECS: user_agent.original.
	UserAgent string

	// SourceIP is the address from which the event originated.
	// OWASP: source address. ECS: source.ip.
	SourceIP string

	// SourcePort is the source network port, when known.
	// ECS: source.port.
	SourcePort int

	// DestinationPort is the destination network port, when known.
	// ECS: destination.port.
	DestinationPort int

	// HostIP is the address of the host handling the event.
	// OWASP: application address. ECS: host.ip.
	HostIP string

	// HostName is the hostname of the host handling the event.
	// OWASP: application address. ECS: host.hostname.
	HostName string

	// Protocol identifies the protocol used by the request or connection.
	// OWASP: service/protocol. ECS: network.protocol.
	Protocol string

	// OWASPPort is the generic port value used by the OWASP profile.
	OWASPPort int

	// RequestURI is the original request URI or path.
	// OWASP: entry point URL. ECS: url.original.
	RequestURI string

	// RequestMethod is the original HTTP request method.
	// OWASP: HTTP method. ECS: http.request.method.
	RequestMethod string

	// Region identifies the deployment or processing region.
	// OWASP: geolocation/deployment context. ECS: cloud.region.
	Region string

	// OWASPGeo is the geolocation value used by the OWASP profile.
	OWASPGeo string

	// SourceGeo describes the source location for ECS source.geo.* fields.
	SourceGeo GeoFields

	// DestinationGeo describes the destination location for ECS
	// destination.geo.* fields.
	DestinationGeo GeoFields

	// ServiceVersion identifies the version of the emitting service.
	// ECS: service.version.
	ServiceVersion string

	// HTTPStatusCode is the response status, when an HTTP response exists.
	// OWASP: HTTP status code. ECS: http.response.status_code.
	HTTPStatusCode int
}

// GeoFields contains the structured location values supported by ECS geo
// fields. Empty members are omitted by the ECS model.
type GeoFields struct {
	CityName       string
	CountryISOCode string
	CountryName    string
	ContinentCode  string
	ContinentName  string
	RegionName     string
	RegionISOCode  string

	// Location is the geo point of the location, or nil when it is not
	// supplied. It is a pointer because zero is a valid latitude and a
	// valid longitude. It must be treated as immutable once supplied, as
	// it is not copied.
	Location *GeoPoint
}

// GeoPoint is an ECS geo point. The ECS model emits the coordinates as they
// are given, without range validation.
type GeoPoint struct {
	Latitude  float64
	Longitude float64
}

// merge returns the combination of f and override, where every non-zero
// member of override replaces the corresponding member of f.
func (f Fields) merge(override Fields) Fields {
	// The merge is written out explicitly rather than through reflection so that
	// it stays allocation free on the logging hot path.
	result := f
	if override.TraceID != "" {
		result.TraceID = override.TraceID
	}
	if override.SpanID != "" {
		result.SpanID = override.SpanID
	}
	if override.TransactionID != "" {
		result.TransactionID = override.TransactionID
	}
	if override.UserAgent != "" {
		result.UserAgent = override.UserAgent
	}
	if override.SourceIP != "" {
		result.SourceIP = override.SourceIP
	}
	if override.SourcePort != 0 {
		result.SourcePort = override.SourcePort
	}
	if override.DestinationPort != 0 {
		result.DestinationPort = override.DestinationPort
	}
	if override.HostIP != "" {
		result.HostIP = override.HostIP
	}
	if override.HostName != "" {
		result.HostName = override.HostName
	}
	if override.Protocol != "" {
		result.Protocol = override.Protocol
	}
	if override.OWASPPort != 0 {
		result.OWASPPort = override.OWASPPort
	}
	if override.RequestURI != "" {
		result.RequestURI = override.RequestURI
	}
	if override.RequestMethod != "" {
		result.RequestMethod = override.RequestMethod
	}
	if override.Region != "" {
		result.Region = override.Region
	}
	if override.OWASPGeo != "" {
		result.OWASPGeo = override.OWASPGeo
	}
	result.SourceGeo = f.SourceGeo.merge(override.SourceGeo)
	result.DestinationGeo = f.DestinationGeo.merge(override.DestinationGeo)
	if override.ServiceVersion != "" {
		result.ServiceVersion = override.ServiceVersion
	}
	if override.HTTPStatusCode != 0 {
		result.HTTPStatusCode = override.HTTPStatusCode
	}
	return result
}

// merge returns the combination of g and override, where every non-zero
// member of override replaces the corresponding member of g.
func (g GeoFields) merge(override GeoFields) GeoFields {
	result := g
	if override.CityName != "" {
		result.CityName = override.CityName
	}
	if override.CountryISOCode != "" {
		result.CountryISOCode = override.CountryISOCode
	}
	if override.CountryName != "" {
		result.CountryName = override.CountryName
	}
	if override.ContinentCode != "" {
		result.ContinentCode = override.ContinentCode
	}
	if override.ContinentName != "" {
		result.ContinentName = override.ContinentName
	}
	if override.RegionName != "" {
		result.RegionName = override.RegionName
	}
	if override.RegionISOCode != "" {
		result.RegionISOCode = override.RegionISOCode
	}
	if override.Location != nil {
		result.Location = override.Location
	}
	return result
}

type fieldsContextKey struct{}

// ContextWithFields returns a copy of ctx carrying the given fields, which are
// included in every log call made with the returned context.
//
// The non-zero members override the fields already stored in ctx, and override
// the logger's default fields at log time. The parent context is never
// modified.
func ContextWithFields(ctx context.Context, fields Fields) context.Context {
	if fields == (Fields{}) {
		return ctx
	}

	result := fields
	if previous := fieldsFromContext(ctx); previous != nil {
		result = previous.merge(fields)
	}
	return context.WithValue(ctx, fieldsContextKey{}, &result)
}

// fieldsFromContext extracts the fields stored in ctx, or nil when none are
// present. The returned value must be treated as immutable.
func fieldsFromContext(ctx context.Context) *Fields {
	fields, _ := ctx.Value(fieldsContextKey{}).(*Fields)
	return fields
}
