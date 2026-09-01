# go-seclog implementation specification

## Goals

The new module will be `github.com/canonical/go-seclog`, with the root
package named `seclog`. It will:

- use the standard library `log/slog` implementation;
- provide a closed, documented `Fields` struct so callers use known field
  names instead of free-form strings;
- support both an OWASP security-log profile and an ECS profile;
- keep field merging independent from output field names;
- retain the current OWASP event identifiers and descriptions unless a
  deliberate compatibility change is approved;
- make event constructors available from
  `github.com/canonical/go-seclog/event`;
- keep the model boundary open for additional schemas later;
- avoid mutable shared configuration and unnecessary reflection or allocation
  on the logging hot path.

This is a new module and package name. It will not retain a zap compatibility
layer or a dependency on `go.uber.org/zap`. The README will include a
migration table from the old `zapseclog` API.

## Findings from the standards

### OWASP

The [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
does not define a formal, fixed JSON schema or a mandatory list of exact field
names. It recommends that application logs capture "when, where, who and
what", with commonly useful properties including:

- timestamp and interaction identifier;
- application identifier and application address;
- service, protocol, and geolocation;
- entry-point URI and HTTP method;
- source address and user identity;
- event type, severity, security-event classification, and description.

It also recommends recording action, object, result, reason, HTTP status,
user-agent, and other details where relevant. Authentication successes and
failures, authorization failures, system events, startup/shutdown, and
higher-risk administrative actions are examples of events to log. OWASP also
recommends sanitization and warns against logging secrets, credentials, access
tokens, and sensitive personal data.

Therefore, this package will define an organization-level OWASP profile with
stable names and required output fields. Those names are the package contract,
not names mandated by OWASP itself. The profile will retain the old output
keys (`appid`, `event`, `type`, `severity`, and `description`) and the
timestamp key (`datetime`).

### ECS

The [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
defines related field sets rather than one event-specific record shape. The
Base field set is at the root; other sets are nested objects. ECS field
metadata distinguishes `core` and `extended` fields, but those levels do not
mean every field is required for every event. The Base documentation
explicitly identifies `@timestamp` as required for all events. Fields such as
`service.name`, `event.action`, `event.category`, `event.type`, and
`event.outcome` are core fields with defined semantics, but should be emitted
when applicable.

ECS does have a different event vocabulary from the current OWASP identifiers:

- `event.action` is an implementer-defined specific action, such as
  `user-password-change`;
- `event.category` is an array constrained to values such as `authentication`,
  `iam`, `process`, `session`, and `web`;
- `event.type` is an array constrained to values such as `access`, `admin`,
  `change`, `creation`, `deletion`, `denied`, `error`, `start`, and `user`;
- `event.kind` is a high-level value such as `event` or `alert`;
- `event.outcome` is `success`, `failure`, or `unknown`;
- `event.severity` is numeric and represents source severity;
- `message` is the human-readable log message;
- `@timestamp` is the event timestamp.

For example, `authn_login_success` is a useful OWASP-style stable event
identifier, while an ECS representation of the same event could use
`event.action: user-login`, `event.category: ["authentication"]`,
`event.type: ["access"]`, and `event.outcome: success`. The models must not
pretend these vocabularies are interchangeable.

The initial ECS model will use the ECS field names and semantics above. It
will not claim that `appid` or a description field is an ECS requirement.
The configured application ID will map to `service.name`, while the message
will be emitted as `message`.

## Package layout

```text
.
|-- logger.go          # Logger, Setup, options, and Log methods
|-- fields.go          # Closed Fields type, merging, and context helpers
|-- model.go           # Event, EventContext, EventFunc, and Model interface
|-- principal.go       # Principal and principal context helpers
|-- owasp.go           # OWASP model and default slog handler configuration
|-- ecs.go             # ECS model and default slog handler configuration
|-- logger_test.go
|-- fields_test.go
|-- principal_test.go
|-- model_test.go
`-- event/
    |-- authentication.go
    |-- authorization.go
    |-- system.go
    |-- user.go
    `-- event_test.go
```

The `event` package imports `seclog` for shared event types and context
access. The root package does not import `event`, avoiding an import cycle and
allowing applications to define their own event constructors.

## Closed Fields contract

The public field type will be a closed struct:

```go
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
    // OWASP: service/protocol. ECS: network.protocol when applicable.
    Protocol string

    // OWASPPort is the generic port value used by the OWASP profile.
    // Use SourcePort or DestinationPort when the ECS model is selected.
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
    // Use SourceGeo or DestinationGeo when the ECS model is selected.
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
    CityName      string
    CountryISOCode string
    CountryName   string
    ContinentCode string
    ContinentName string
    RegionName    string
    RegionISOCode string
    Location      *GeoPoint
}

// GeoPoint is an ECS geo point. The ECS model emits geo.location whenever a
// point is supplied, including coordinates that are zero.
type GeoPoint struct {
    Latitude  float64
    Longitude float64
}
```

This is the initial closed contract, not a promise to model every field in the
ECS catalog. New supported fields will be added to `Fields` with godoc and
model mappings. A field that is not in this struct is intentionally not part
of the package API; callers cannot accidentally emit `traceid` or
`traceId` through this package.

The public names intentionally identify the model or network role where the
meaning differs. The principle is that the public Go name and its type are the
stable input contract, while each model chooses its output representation.

The initial mapping direction is:

| `Fields` member | OWASP output | ECS output | Notes |
| --- | --- | --- | --- |
| `TraceID` | `trace_id` | `trace.id` | Direct mapping |
| `SpanID` | optional `span_id` | `span.id` | ECS-oriented |
| `TransactionID` | optional `transaction_id` | `transaction.id` | ECS-oriented |
| `UserAgent` | `useragent` | `user_agent.original` | Direct source value |
| `SourceIP` | `source_ip` | `source.ip` | Direct mapping |
| `SourcePort` | optional `source_port` | `source.port` | Numeric in ECS |
| `DestinationPort` | optional `destination_port` | `destination.port` | Numeric in ECS |
| `HostIP` | `host_ip` | `host.ip` | Direct mapping |
| `HostName` | `hostname` | `host.hostname` | Direct mapping |
| `Protocol` | `protocol` | `network.protocol` | ECS mapping is contextual |
| `OWASPPort` | `port` | omitted | OWASP's generic port field |
| `RequestURI` | `request_uri` | `url.original` | Original path or URL |
| `RequestMethod` | `request_method` | `http.request.method` | Original casing |
| `Region` | `region` | `cloud.region` | Deployment or processing region |
| `OWASPGeo` | `geo` | omitted | OWASP's generic location field |
| `SourceGeo` | omitted | `source.geo.*` | Structured ECS source location |
| `DestinationGeo` | omitted | `destination.geo.*` | Structured ECS destination location |
| `ServiceVersion` | optional `service_version` | `service.version` | ECS-oriented |
| `HTTPStatusCode` | `http_status_code` | `http.response.status_code` | Numeric in ECS |

There is no `ServiceName` member. The service identity is the configured
application ID, which the ECS model emits as `service.name`, so a second
input for the same output cannot disagree with it.

Zero-valued members are omitted from the output by every model. A field is
either supplied or absent, so a caller cannot emit `port: 0` or
`http_status_code: 0`. This keeps merging and output consistent and avoids
distinguishing "unset" from "explicitly zero" without presence bits.

The table describes the initial implementation direction, not a promise that
every row will be emitted by every model. In particular, the OWASP model can
retain useful organization-specific fields while the ECS model must omit or
restructure values that do not satisfy ECS semantics.

### Why not runtime struct tags?

Tags such as `` `owasp:"trace_id" ecs:"trace.id"` `` are possible, but they
are not the preferred runtime design:

- tags do not validate that a mapping is semantically correct;
- ECS mappings are conditional and sometimes nested, so one tag is
  insufficient for fields such as the role-specific ports, structured
  locations, and `RequestURI`;
- reflection on every log call conflicts with the performance goal;
- explicit mapping functions are easy to review, compile-time visible, and
  can append typed `slog.Attr` values without intermediate maps.

Each model will therefore explicitly map `Fields` to output attributes. If
the field list becomes large, tags may be used by a `go:generate` tool to
produce static mapping code, but reflection will not run in production.

## Field merging

`Fields` is a value type whose zero values mean "not supplied". A non-zero
field in a later source replaces the corresponding non-zero field in an
earlier source. This preserves the old behavior and permits efficient
field-by-field merging without reflection:

```go
func (f Fields) merge(override Fields) Fields {
    result := f
    if override.TraceID != "" {
        result.TraceID = override.TraceID
    }
    // The implementation repeats this explicit operation for each field.
    return result
}
```

`GeoFields.Location` is the exception to the zero-value rule, because zero is
a valid latitude and a valid longitude. Presence is explicit: it is a
`*GeoPoint`, a non-nil pointer replaces the earlier location and is always
emitted, and nil means "not supplied". The pointed-to value is not copied, so
it must be treated as immutable once it is supplied.

The implementation will use one complete explicit merge function, not a
partial example. Numeric zero and nil values mean unset; a future need to
explicitly clear an inherited value will require presence bits or pointer
fields and a deliberate API decision.

Merge precedence is:

1. logger default fields are the base;
2. context fields override logger fields;
3. fields supplied by `LogWith` override both.

There is no fourth, event-specific layer.

The logger stores an immutable copy of its default `Fields`. Context helpers
store an immutable copy as well, and never mutate a parent context. Because
the type is closed and mappings are explicit, the logger can merge the
struct once and let the selected model append only the fields it supports.
There is no `Field` alias for `slog.Attr`; `slog.Attr` is an internal output
type, while `Fields` is the user-facing input contract.

## Core event API

The root package will expose model-neutral event semantics:

```go
type Severity string

const (
    SeverityInfo     Severity = "INFO"
    SeverityWarn     Severity = "WARN"
    SeverityCritical Severity = "CRITICAL"
)

type Outcome string

const (
    OutcomeSuccess Outcome = "success"
    OutcomeFailure Outcome = "failure"
    OutcomeUnknown Outcome = "unknown"
)

type Event struct {
    // Name is the stable package event identifier, such as
    // "authn_login_success". OWASP emits this as event.
    Name string

    // Action is the model-neutral action. ECS emits event.action.
    Action string

    // Categories and Types use ECS's constrained values when populated.
    // OWASP does not need to emit these values.
    Categories []string
    Types      []string

    // Outcome is used by models that represent success/failure explicitly.
    Outcome Outcome

    // Kind is the ECS event kind. OWASP does not emit this field.
    Kind string

    // Severity is the security significance of the event. OWASP emits its
    // textual value; ECS maps it to the package's numeric convention.
    Severity Severity

    // Qualifiers preserve the current OWASP event suffix format.
    Qualifiers []string

    // Description is the human-readable event message.
    Description string

    // Reason is an optional structured explanation of the outcome.
    Reason string
}

// EventContext carries the resolved, model-neutral values that an event
// constructor may need at log time. It is a struct so that new members can
// be added without breaking existing constructors.
type EventContext struct {
    // Principal is the actor resolved from the logging context. It may be
    // nil; a nil principal renders as "unknown".
    Principal *Principal

    // Fields is the merged field set for this log call.
    Fields Fields
}

type EventFunc func(EventContext) Event
```

Event construction stays deferred rather than returning a finished `Event`
from the constructor. The principal appears at an event-specific position in
both the OWASP qualifiers and the description arguments, so a finished
`Event` would force the logger to inject it afterwards through a qualifier
sentinel or a description format convention. For example,
`authn_token_revoked` renders `Token <id:%s> was revoked for user %s` from
`(tokenID, principal)`, `user_created` places the principal first among three
qualifiers, and `sys_crash` has no principal at all. Deferred construction
also avoids formatting a description when the handler is not enabled.

`Event` has no `Fields` member. Event-specific values are carried by the
OWASP qualifiers and the model-neutral properties; a per-event field set
would need a precedence rule against the merged logger, context, and
per-call fields without a constructor that currently requires one.

`EventContext` replaces the old `context.Context` parameter. The logger
resolves the principal and merges fields once per `Log` call rather than once
per event, constructors become testable without building a context, and event
functions cannot reach arbitrary context values. A constructor that needs an
application-specific context value captures it at the call site, which always
has the context in hand:

```go
seclog.Log(ctx, myapp.PaymentProcessed(tenantFrom(ctx)))
```

The event constructors will populate the model-neutral properties that are
known from the event. For example, a successful login can retain
`Name: "authn_login_success"` and its existing description while also setting
`Action: "user-login"`, `Categories: []string{"authentication"}`,
`Types: []string{"access"}`, `Kind: "event"`, and
`Outcome: OutcomeSuccess`. The initial classifications are specified below
and must use only ECS allowed values.

| Constructor | `event.action` | `event.category` | `event.type` | `event.outcome` |
| --- | --- | --- | --- | --- |
| `AuthenticationLoginSuccess` | `user-login` | `authentication` | `access` | `success` |
| `AuthenticationLoginFail` | `user-login` | `authentication` | `access` | `failure` |
| `AuthenticationLoginFailMaxTries` | `user-login-failure-limit` | `authentication` | `denied` | `failure` |
| `AuthenticationLoginLock` | `user-account-lock` | `iam` | `change` | `success` |
| `AuthenticationPasswordChange` | `user-password-change` | `iam` | `change` | `success` |
| `AuthenticationPasswordChangeFail` | `user-password-change` | `iam` | `change` | `failure` |
| `AuthenticationTokenCreated` | `user-token-create` | `iam` | `creation` | `success` |
| `AuthenticationTokenRevoked` | `user-token-revoke` | `iam` | `deletion` | `success` |
| `AuthenticationTokenReuse` | `user-token-reuse` | `authentication` | `denied` | `failure` |
| `AuthenticationTokenDelete` | `user-token-delete` | `iam` | `deletion` | `success` |
| `AuthorizationFail` | `authorization-check` | `iam` | `denied` | `failure` |
| `AuthorizationAdmin` | caller's `action` | `iam` | `admin` | `unknown` |
| `SystemStartup` | `system-start` | `process` | `start` | `success` |
| `SystemShutdown` | `system-stop` | `process` | `end` | `success` |
| `SystemRestart` | `system-restart` | `process` | `change` | `success` |
| `SystemCrash` | `system-crash` | `process` | `error` | `failure` |
| `SystemMonitoringDisabled` | `monitoring-disable` | `host` | `change` | `success` |
| `UserCreated` | `user-create` | `iam` | `creation` | `success` |
| `UserUpdated` | `user-update` | `iam` | `change` | `success` |

Every constructor sets `Kind: "event"` and the listed ECS metadata. The
mapping is intentionally separate from the OWASP `Name` and qualifier
format.

`AuthorizationAdmin` is the one constructor whose ECS action is supplied by
the caller: its `action` argument becomes `event.action` verbatim, since the
package cannot know which administrative operation was performed. The
category and type stay fixed at `iam` and `admin`.

The constructors move and are shortened as follows:

```go
event.AuthenticationLoginSuccess()
event.AuthenticationLoginFail()
event.AuthenticationLoginFailMaxTries(maxAttempts)
event.AuthenticationLoginLock(reason)
event.AuthenticationPasswordChange()
event.AuthenticationPasswordChangeFail()
event.AuthenticationTokenCreated(entitlements...)
event.AuthenticationTokenRevoked(tokenID)
event.AuthenticationTokenReuse(tokenID)
event.AuthenticationTokenDelete()

event.AuthorizationFail(resource)
event.AuthorizationAdmin(action, details)

event.SystemStartup()
event.SystemShutdown()
event.SystemRestart()
event.SystemCrash(reason)
event.SystemMonitoringDisabled(monitor)

event.UserCreated(userID, attributes...)
event.UserUpdated(userID, attributes...)
```

The login-lock reason type and constants move to `event` with shorter names
such as `event.LoginLockReasonMaxRetries`. Constructors read the principal
from `EventContext` instead of the context, but the resulting OWASP event
identifiers, qualifier order, and description text remain unchanged.
Event-specific values such as a token ID or resource remain in the OWASP
qualifiers, and are additionally represented in the model-neutral properties
when an ECS mapping needs them.

The constructors taking variadic values join them at construction time rather
than inside the returned `EventFunc`. A constructed event therefore snapshots
its arguments and does not retain the caller's slice, so mutating that slice
later cannot change a record or race with a concurrent log call, and the
`strings.Join` allocation stays out of the logging path.

## Context API

Logger options and context helpers need distinct names:

```go
ctx = seclog.ContextWithPrincipal(ctx, principal)
ctx = seclog.ContextWithFields(ctx, seclog.Fields{
    TraceID:    traceID,
    RequestURI: "/login",
})
```

`ContextWithFields` and `ContextWithPrincipal` are the canonical context
helpers, with the signatures:

```go
func ContextWithPrincipal(ctx context.Context, principal *Principal) context.Context
func ContextWithFields(ctx context.Context, fields Fields) context.Context
```

All `WithX` names are reserved for logger options, so the old
`WithPrincipal` name is not retained.

The principal is a single concrete type. The old `LoggablePrincipal`
interface is removed: it only exposed `String()`, so a model could never
recover the structure that ECS `user.*` requires, and every implementation
had to reproduce the OWASP rendering anyway.

```go
// Principal identifies the main actor of a security event.
type Principal struct {
    // Account is the account or login identifier of the actor.
    // ECS: user.name.
    Account string

    // ServiceAccount is the service identity acting in this event.
    // ECS: user.name when Account is empty, otherwise user.effective.name.
    ServiceAccount string

    // Email is the actor's email address.
    // ECS: user.email.
    Email string

    // Name is the actor's human-readable display name.
    // ECS: user.full_name.
    Name string
}

func (p *Principal) String() string
```

`String()` has a pointer receiver and handles a nil receiver, so event
constructors can call `ec.Principal.String()` unconditionally. It returns
`unknown` for a nil principal or one with no populated members, and
otherwise renders the non-empty members in the fixed order
`<account:a,service_account:s,email:e,name:n>`. `Name` is appended last so
that existing rendered values are unchanged for callers that do not set it.

The ECS principal mapping is:

| `Principal` member | ECS output |
| --- | --- |
| `Account` | `user.name` |
| `ServiceAccount` | `user.name` when `Account` is empty, otherwise `user.effective.name` |
| `Email` | `user.email` |
| `Name` | `user.full_name` |

`user.effective.*` is the ECS location for the identity whose privileges are
actually in use, which is the correct place for a service account acting on
behalf of a named account. When the principal is nil or empty, the ECS model
omits `user.*` entirely rather than emitting `user.name: "unknown"`, because
`unknown` is an OWASP rendering convention and not a real user name. The
OWASP model continues to embed `unknown` in the `event` value through the
qualifiers.

Context keys remain unexported typed keys. The logger resolves the principal
and fields from the context once per `Log` call and passes them to event
constructors through `EventContext`; neither value is stored in global
state.

## Logger configuration and call forms

Logger configuration is immutable after construction:

```go
type Option func(*config)

func NewLogger(appID string, options ...Option) *Logger
func Setup(appID string, options ...Option)
func WithFields(fields Fields) Option
func WithModel(model Model) Option
func WithWriter(w io.Writer) Option
func WithHandler(handler slog.Handler) Option
func WithErrorHandler(errorHandler func(error)) Option

func NewOWASPModel() Model
func NewECSModel() Model
func NewOWASPHandler(w io.Writer) slog.Handler
func NewECSHandler(w io.Writer) slog.Handler
```

The built-in models are exposed as constructors rather than as exported
package variables, so that no consumer can reassign them and change the
behavior of unrelated loggers, or leave a nil model behind. Both models are
stateless, so the returned values can be shared freely and compare equal.
Constructors also leave room for per-model options later.

`NewLogger` returns no error as approved. Built-in options have no expected
runtime failure. A nil option, or an option carrying a nil model, handler,
writer or error handler, is silently ignored and leaves the current value in
place, so a partially built configuration still produces a working logger
instead of one that silently drops events.

The default model is OWASP. If `WithHandler` is not provided, `NewLogger`
selects the handler appropriate for the selected model and writes JSON to the
configured writer, `os.Stdout` by default: the OWASP handler uses `datetime`
and `description`, while the ECS handler uses `@timestamp` and `message`.
`WithWriter` therefore changes the destination without changing the output
contract, and `WithHandler` is primarily for tests and integrations with an
existing handler. The explicit handler always wins regardless of option order,
and makes `WithWriter` ineffective.

The model envelope belongs to the handler, not to `Model.AppendAttrs`, so an
unrelated handler preserves only the model attributes: the timestamp, message,
and level keys revert to that handler's configuration. This limit is
documented rather than worked around, because a generic `slog.Handler` cannot
be forced to serialize a particular envelope. `NewOWASPHandler` and
`NewECSHandler` export the built-in handlers, so an integration that must keep
the envelope can compose them, for example with buffering or fan-out, instead
of asserting `NewOWASPModel().(HandlerProvider)`. `HandlerProvider` remains the
extension point for custom models.

`Log` does not return an error, following `slog.Logger`. Because a record that
the handler fails to emit is a lost security event, `WithErrorHandler`
registers a callback receiving the error returned by `slog.Handler.Handle`. It
is called synchronously, once per failed record, from the calling goroutine,
and the remaining events of the call are still emitted. Without it, handler
errors are discarded.

The package-level logger is stored in an `atomic.Pointer[Logger]`.
`Setup` atomically replaces a complete logger configuration, so concurrent
calls to setup and logging do not observe partially updated app IDs, fields,
models, or handlers. Until `Setup` is called, the package-level logger uses
the application ID `unknown` and the OWASP model, so early events are still
emitted in a valid shape.

`NewLogger` normalizes an empty application ID to `unknown`, which matches
that package-level default. It has no error return, and an empty ID is likely
to be accidental: OWASP would emit an empty `appid`, while ECS would omit
`service.name` entirely, leaving records hard to route and attribute.

Options are applied in order and each one replaces the previous value for
that setting. Two `WithFields` calls do not merge; the last one wins. Only
the merge precedence between logger, context, and per-call fields is
additive.

The primary logging API remains concise:

```go
seclog.Log(ctx, event.AuthenticationLoginSuccess())

logger := seclog.NewLogger(
    "my-app",
    seclog.WithFields(seclog.Fields{Region: "us-east-1"}),
    seclog.WithModel(seclog.NewOWASPModel()),
)
logger.Log(ctx, event.AuthenticationLoginSuccess())
```

Per-call fields are supplied without inventing field names:

```go
logger.LogWith(
    ctx,
    &seclog.Principal{Account: "user"},
    seclog.Fields{TraceID: traceID},
    event.AuthenticationLoginSuccess(),
)
```

`LogWith` derives a context and delegates to `Log`; it does not create a
second logging path. Package-level `LogWith` has the same signature. A non-nil
principal replaces the one in the context, nil keeps it, and `&Principal{}`
logs an unknown actor explicitly.

The logging API is:

```go
func (l *Logger) Log(ctx context.Context, events ...EventFunc)
func (l *Logger) LogWith(
    ctx context.Context,
    principal *Principal,
    fields Fields,
    events ...EventFunc,
)

func Log(ctx context.Context, events ...EventFunc)
func LogWith(
    ctx context.Context,
    principal *Principal,
    fields Fields,
    events ...EventFunc,
)
```

Go cannot overload `Log` to support both `Log(ctx, events...)` and
`Log(ctx, Fields{...}, events...)` while keeping both calls strongly typed.
The API therefore keeps `Log` for events and uses `LogWith` for per-call
`Fields`. `LogWith` is the preferred convenience for one-off principal and
field values; `ContextWithFields` is preferred when the same values apply to
multiple log calls.

No `SetAppID` or `SetDefaultFields` mutators will be carried forward.
Applications needing another configuration construct a new logger or call
`Setup`. This removes the old logger mutex and prevents configuration changes
while another goroutine is logging.

## Model interface and output

The model owns output field selection and mapping. It receives the resolved
principal and the merged closed `Fields` value, and can ignore anything that
is not meaningful for its schema:

```go
type Model interface {
    // Name identifies the model for diagnostics and documentation.
    Name() string

    // AppendAttrs appends model-specific attributes to dst. It must not
    // mutate event, principal, or fields, and it must not return reserved
    // attributes owned by the logger/handler unless documented by the model.
    AppendAttrs(
        dst []slog.Attr,
        appID string,
        event Event,
        principal *Principal,
        fields Fields,
    ) []slog.Attr
}
```

The principal is passed separately from the event because a rendered
qualifier string is lossy. OWASP needs the principal inline in the `event`
value, which the constructor already produced, while ECS needs structured
`user.*` values that cannot be recovered from `<account:username1>`. The
principal is therefore represented twice on purpose: as an OWASP qualifier
string inside `Event`, and as structure passed to the model. The OWASP model
ignores the structured principal; the ECS model maps it and ignores the
qualifiers. `principal` may be nil, which every model must tolerate.

The interface deliberately does not expose a map or require reflection.
`AppendAttrs` lets a model append typed attributes directly and decide which
fields are required, optional, nested, or unsupported. The logger emits the
event description as the slog message and uses the model's documented record
level. Timestamp handling remains the responsibility of the slog handler.

The model's documentation and tests are the source of truth for required
output. A model does not need to emit every member of `Fields`.

Event wording stays in the event constructors rather than the models. The
description text is per-event and shared across schemas, so moving it into
models would duplicate every message once per model and would make
application-defined events unrenderable by a model that does not know them.
The resulting layering is:

| Layer | Responsibility |
| --- | --- |
| Event constructor | Event identity, ECS semantics, severity, wording, OWASP qualifiers |
| Model | Output field names, structure, and which values are emitted |
| Logger | Context resolution, field merging, event evaluation, record emission |

### Logging pipeline

Each `Log` call performs the following steps in order:

1. return immediately when no events are provided;
2. check whether the handler is enabled and return early if it is not, so a
   disabled logger stays allocation-free;
3. resolve the principal from the context, which may yield nil;
4. merge logger default fields, context fields, and any per-call fields;
5. build one `EventContext` and evaluate every `EventFunc` with it;
6. call the model's `AppendAttrs` for each resulting event;
7. emit one slog record per event, using the event description as the message,
   and report any handler error to the configured error handler.

### OWASP model

`NewOWASPModel` will emit:

- `appid`: configured application ID;
- `event`: `Name`, followed by `:` and comma-separated qualifiers;
- `type`: `"security"`;
- `severity`: textual security severity (`INFO`, `WARN`, or `CRITICAL`);
- optional supported values from `Fields`.

The `event` value preserves the current formatting exactly, including its
edge cases: the `:` separator is appended only when at least one qualifier
exists, and empty qualifiers are still rendered. Values such as `sys_crash:`
for an empty crash reason and `authn_token_created:unknown,` for a token
created with no entitlements remain byte-identical to the old package, and
tests assert them.

The default OWASP handler will use `slog.NewJSONHandler` with a replacement
attribute function:

- `time` becomes `datetime`, using
  `2006-01-02T15:04:05-07:00`;
- `msg` becomes `description`;
- `level` remains `level` and is always `INFO` for security records.

This preserves the old package's distinction between ordinary logger level
and security severity. The OWASP profile's required fields are this package's
contract, not a claim that OWASP mandates those exact keys.

### ECS model

`NewECSModel` will emit ECS names and types, including as applicable:

- `@timestamp` through the handler's time field;
- `message` through the slog message;
- `service.name` from the configured application identity;
- `event.action`, `event.category`, `event.type`, `event.kind`, and
  `event.outcome` from `Event`;
- numeric `event.severity` using the package mapping `INFO=1`, `WARN=2`, and
  `CRITICAL=3`;
- `log.level` as the textual severity, so the ECS output remains readable
  without knowing the numeric convention;
- `user.*` from the principal, omitted entirely when no principal is present;
- mapped fields such as `trace.id`, `span.id`, `transaction.id`,
  `source.ip`, `source.port`, `host.ip`, `host.hostname`,
  `http.request.method`, `http.response.status_code`, `url.original`,
  and `user_agent.original`.

The exact ECS mapping for each `Fields` member will be explicit and tested.
Ambiguous OWASP fields are not forced into an incorrect ECS field merely
because a similarly named destination exists. `OWASPPort` and `OWASPGeo` are
used only with the OWASP model; `SourcePort`, `DestinationPort`, `SourceGeo`,
and `DestinationGeo` are used for ECS. `RequestURI` maps to `url.original`
because it represents the original request URI or path.

The ECS handler will use ECS-compatible keys, notably `@timestamp` and
`message`, rather than the OWASP `datetime` and `description` aliases. ECS
does not require an `appid` field; the application identity maps to
`service.name`.

## Performance, safety, and validation

The implementation will:

- use explicit struct merge code and explicit model mappings;
- avoid runtime reflection and intermediate maps;
- copy `Fields` values and any mutable members when accepting logger or
  context configuration;
- avoid allocating a merged field representation when no context or per-call
  override exists;
- build one `EventContext` per `Log` call and evaluate each `EventFunc` once,
  emitting one slog record per event;
- sanitize or reject event data according to the package's documented log
  injection policy, while never logging secrets or credentials by default.

Tests will:

- use `github.com/frankban/quicktest`, as the old package did, so the
  assertion style carries over; it is the module's only dependency;
- follow the repository's unit test skill: table-driven cases, one `TestXxx`
  per function under test, named helpers for complex setup, and no branching
  inside the table loop;
- use an injected `slog.Handler` to capture records directly;
- use JSON handlers for OWASP and ECS schema assertions;
- decode JSON by key and ignore nondeterministic timestamps;
- retain table-driven coverage for principals, field precedence, every event
  constructor, multiple events, and package-level setup;
- assert the OWASP `event` formatting edge cases and the omission of
  zero-valued fields and of an absent ECS principal;
- exercise event constructors directly with a literal `EventContext`, without
  building a context or a logger;
- verify that one `Log` call resolves the principal and merges fields once and
  passes the same `EventContext` to every event;
- verify that unsupported fields are omitted by each model;
- verify duplicate/override behavior and preservation of parent contexts;
- run concurrent logging and setup tests under the race detector where
  supported.

Benchmarks will cover one event with no fields, default fields, contextual
overrides, and multiple events. Results will be compared with the old
package as a reference, with correctness and ownership guarantees taking
precedence over an unsafe zero-allocation shortcut.

## Implementation sequence

1. Add `Fields`, explicit merge/clone code, principal context helpers, and
   the model-neutral `Event`, `EventContext`, and `EventFunc` types.
2. Implement `Model`, `NewOWASPModel`, and the OWASP-compatible slog handler.
3. Implement `NewECSModel` and its ECS-compatible handler and field mappings.
4. Implement immutable `Logger`, options, atomic package-level `Setup`,
   `Log`, and `LogWith`.
5. Move and shorten event constructors into the `event` subpackage, adding
   ECS semantic metadata and tests.
6. Port the old tests to standard-library slog handlers, then add model,
   unsupported-field, concurrency, race, and benchmark coverage.
7. Update README and examples with setup, context, field, and migration
   documentation.
8. Remove zap-only files and dependencies, format the module, and run the
   targeted tests followed by the full package suite.

The module targets Go 1.25, matching the `go-version: '1.25.x'` pin in the PR
workflow. The `go` directive in `go.mod` is `go 1.25`, so any 1.25 patch
release satisfies it and CI does not download a different toolchain. The
implementation must not use language or standard library features newer than
1.25. The workflow collects coverage only for the root package, so the
`event` subpackage needs its own coverage target if that matters.

## Decisions now incorporated

1. Use a closed typed `Fields` struct, not `OptionalFields` and not free-form
   `slog.Attr` input.
2. Keep `NewLogger` without an error return.
3. Keep setup options separate from context helpers; use
   `ContextWithFields` and `ContextWithPrincipal` for request-scoped values.
4. Keep the `Setup` idea with immutable logger instances and atomic global
   replacement.
5. Support both OWASP and ECS with separate model mappings and output
   handlers.

## Implementation defaults requiring no further review

The following decisions are now fixed for implementation:

1. `LogWith(ctx, principal, fields, events...)` is the only per-call field
   convenience. There is no `LogFields` method and `Log` remains
   event-only.
2. Ambiguous fields are split by profile or network role:
   `OWASPPort` and `OWASPGeo` are OWASP-only; `SourcePort`, `DestinationPort`,
   `SourceGeo`, and `DestinationGeo` are ECS-oriented. Their godoc must state
   the model in which each field is meaningful.
3. The configured application ID maps to ECS `service.name`. The ECS model
   does not emit the non-ECS `appid` field.
4. Context manipulation uses only `ContextWithPrincipal` and
   `ContextWithFields`. Logger configuration uses `WithX` option names.
5. ECS `event.severity` uses the package mapping `INFO=1`, `WARN=2`, and
   `CRITICAL=3`. This is the package's source-specific numeric convention,
   not an ECS-defined universal scale.
6. Event construction stays deferred through
   `EventFunc func(EventContext) Event`. The old `EventFn` name and its
   `context.Context` parameter are not retained.
7. The structured principal is passed to `Model.AppendAttrs` in addition to
   the event, so ECS can emit `user.*` values that a rendered OWASP qualifier
   cannot provide.
8. `Principal` is a concrete struct used everywhere; the `LoggablePrincipal`
   interface is removed and `Principal` gains a `Name` member.
9. `Fields` has no `ServiceName` member and `Event` has no `Fields` member.
10. Zero-valued `Fields` members are omitted by every model.
11. `Region` maps to ECS `cloud.region`.
12. The default application ID before `Setup` is `unknown`.
13. Repeated options replace rather than merge; the last one wins.
14. OWASP `event` formatting, including its empty-qualifier edge cases, is
    preserved byte-for-byte and asserted by tests.
15. `AuthorizationAdmin` uses the caller's `action` as ECS `event.action`.
16. Tests use `github.com/frankban/quicktest`.
17. The module targets Go 1.25 (`go 1.25` in `go.mod`, `1.25.x` in CI). No
    feature newer than Go 1.25 may be used.

One deliberate consequence is that `Description` is rendered once by the
constructor, so an ECS `message` contains the principal in the OWASP
rendering, such as `User <account:username1> login successfully`. If
per-model principal rendering is wanted later, `EventContext` can gain a
pre-rendered `PrincipalText` member supplied by the active model. Because
`EventContext` is a struct, that addition would not change the `EventFunc`
signature or any existing constructor.

There are no remaining design questions that block implementation. Details
such as the complete ECS classification for each event constructor and the
final set of additional `Fields` members are implementation work governed by
the standards, explicit godoc, and tests. They do not require changing the
public architecture above.
