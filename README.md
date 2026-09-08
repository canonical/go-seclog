# go-seclog

`go-seclog` enables easy Security Event Logging using the standard library
[log/slog](https://pkg.go.dev/log/slog).

It emits the security events recommended by the
[OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html),
and each event can be emitted in either supported model: the OWASP field names
or the
[Elastic Common Schema](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
ones.

## Installation

```bash
go get github.com/canonical/go-seclog
```

## Usage

### Setting up

Configure the package-level logger with `Setup()`:

```go
seclog.Setup("my-app",
	seclog.WithFields(seclog.Fields{Region: "us-east-1"}),
	seclog.WithModel(seclog.NewOWASPModel()),
)
```

If you cannot set global values, or need one logger per application, create one
with `NewLogger()`. A logger's configuration is immutable, so it is safe for
concurrent use.

```go
logger := seclog.NewLogger("my-app",
	seclog.WithFields(seclog.Fields{Region: "us-east-1"}),
)
```

The available options are `WithFields()`, `WithModel()`, `WithWriter()`,
`WithHandler()` and `WithErrorHandler()`. Each one replaces the previous value
for its setting, so two `WithFields()` calls do not merge. Without options, a
logger uses the OWASP model and writes JSON to `os.Stdout`.

An empty application ID becomes `unknown`, the same identity the package-level
logger uses before `Setup()` is called.

### Loggers in the context

A logger can also travel in the context, with `ContextWithLogger()`. The
package-level `Log()` and `LogWith()` emit with it instead of the package-level
logger, so code called with that context logs with the identity and the
configuration chosen by its caller, without being given a logger:

```go
ctx := seclog.ContextWithLogger(context.Background(), seclog.NewLogger("my-app"))

seclog.Log(ctx, event.SystemStartup()) // logs as "my-app"
```

A `nil` logger leaves the context unchanged, and the methods of a `Logger`
always emit with their receiver, ignoring the logger stored in the context. The
principal and the fields of the context are used as usual.

### Handling emission failures

Like `slog.Logger`, `Log()` does not return an error, and a record that the
handler fails to emit is a lost security event. Use `WithErrorHandler()` to be
notified:

```go
logger := seclog.NewLogger("my-app",
	seclog.WithErrorHandler(func(err error) {
		seclogFailures.Inc() // report a metric, alert, ...
	}),
)
```

The function is called synchronously, once per failed record, and the remaining
events of the call are still emitted. It must be safe for concurrent use, must
not block, and must not log the same event again. Without this option, handler
errors are discarded.

### Logging events

Every event has a constructor in the `event` subpackage, to be used with
`Log()`:

```go
ctx := context.Background()
seclog.Setup("my-app")
logger := seclog.NewLogger("my-other-app")

seclog.Log(ctx, event.SystemStartup()) // package-level logger
logger.Log(ctx, event.SystemStartup()) // dedicated logger

// {"datetime":"...","level":"INFO","description":"User unknown spawned a new instance","appid":"my-app","event":"sys_startup:unknown","type":"security","severity":"WARN"}
// {"datetime":"...","level":"INFO","description":"User unknown spawned a new instance","appid":"my-other-app","event":"sys_startup:unknown","type":"security","severity":"WARN"}
```

Several events can be passed to one call; each one becomes its own record, and
all of them observe the same principal and fields. Constructors that need more
detail, such as an attempt limit or the reason for a lock, take it as an
argument:

```go
seclog.Log(ctx,
	event.AuthenticationLoginFail(),
	event.AuthenticationLoginFailMaxTries(3),
	event.AuthenticationLoginLock(event.LoginLockReasonMaxRetries),
)

// {"datetime":"...","level":"INFO","description":"User <account:johnsurname1> login failed","appid":"my-app","event":"authn_login_fail:<account:johnsurname1>","type":"security","severity":"WARN"}
// {"datetime":"...","level":"INFO","description":"User <account:johnsurname1> reached the login fail limit of 3","appid":"my-app","event":"authn_login_fail_max_tries:<account:johnsurname1>,3","type":"security","severity":"WARN"}
// {"datetime":"...","level":"INFO","description":"User <account:johnsurname1> login locked because maxretries","appid":"my-app","event":"authn_login_lock:<account:johnsurname1>,maxretries","type":"security","severity":"WARN"}
```

> **Note:** The logger always emits security events at slog `level` `INFO`. The
> event's own security significance (`INFO`, `WARN` or `CRITICAL`) is reported
> in the `severity` field instead, so security logs are not mixed with system
> logs by level.

Logging on a `nil` logger is safe: `Log()` and `LogWith()` discard the events,
so an optional logger can be held by an application without a nil check.

```go
var logger *seclog.Logger // never configured

logger.Log(ctx, event.SystemStartup()) // emits nothing
```

### Principals

Almost all events have a main actor, a `Principal`, that is responsible for the
event. Set it with `ContextWithPrincipal()` or `LogWith()`.

```go
ctx := context.Background()
seclog.Setup("my-app")

principal := &seclog.Principal{Account: "johnsurname1"}

// storing it in the context
ctx = seclog.ContextWithPrincipal(ctx, principal)
seclog.Log(ctx, event.AuthenticationLoginSuccess())

// or using LogWith()
seclog.LogWith(ctx, principal, seclog.Fields{}, event.AuthenticationLoginSuccess())

// {"datetime":"...","level":"INFO","description":"User <account:johnsurname1> login successfully","appid":"my-app","event":"authn_login_success:<account:johnsurname1>","type":"security","severity":"INFO"}
```

A principal with no populated member, and a missing principal, both render as
`unknown`.

In `LogWith()`, a non-nil principal replaces the one in the context, `nil`
keeps it, and `&seclog.Principal{}` logs an unknown actor explicitly.

Only the populated members are rendered, joined in a fixed order:

```go
robot := &seclog.Principal{Account: "johnsurname1", ServiceAccount: "deploy-bot"}
seclog.LogWith(ctx, robot, seclog.Fields{}, event.AuthenticationTokenCreated("read", "write"))
seclog.LogWith(ctx, &seclog.Principal{}, seclog.Fields{}, event.AuthenticationLoginFail())

// {"datetime":"...","level":"INFO","description":"A token has been created for <account:johnsurname1,service_account:deploy-bot> with entitlements <read,write>","appid":"my-app","event":"authn_token_created:<account:johnsurname1,service_account:deploy-bot>,read,write","type":"security","severity":"INFO"}
// {"datetime":"...","level":"INFO","description":"User unknown login failed","appid":"my-app","event":"authn_login_fail:unknown","type":"security","severity":"WARN"}
```

### Fields

`Fields` is a closed struct of the contextual values this package knows how to
emit, so callers use documented members instead of free-form field names. A
zero-valued member means "not supplied" and is omitted by every model. The
exception is `GeoFields.Location`, a `*GeoPoint` because zero is a valid
latitude and a valid longitude, where nil means "not supplied".

```go
ctx := context.Background()
seclog.Setup("my-app")

// storing them in the context
ctx = seclog.ContextWithFields(ctx, seclog.Fields{
	TraceID:    "abc-123",
	RequestURI: "/login",
})
seclog.Log(ctx, event.SystemCrash("out-of-memory"))

// or using LogWith()
seclog.LogWith(ctx, nil, seclog.Fields{TraceID: "def-456"}, event.SystemCrash("nil-dereference"))

// {"datetime":"...","level":"INFO","description":"Instance crashed with <reason:out-of-memory>","appid":"my-app","event":"sys_crash:out-of-memory","type":"security","severity":"WARN","trace_id":"abc-123","request_uri":"/login"}
// {"datetime":"...","level":"INFO","description":"Instance crashed with <reason:nil-dereference>","appid":"my-app","event":"sys_crash:nil-dereference","type":"security","severity":"WARN","trace_id":"def-456","request_uri":"/login"}
```

Fields are merged field by field, where a non-zero value replaces the value of
the layer below it:

1. the logger's default fields are the base;
2. the context fields override the logger fields;
3. the fields given to `LogWith()` override both.

### Models

A `Model` owns the output field names and structure of a record. The package
provides two:

| Model | Timestamp | Message | Application ID | Notes |
| --- | --- | --- | --- | --- |
| `seclog.NewOWASPModel()` (default) | `datetime` | `description` | `appid` | Emits `event`, `type` and `severity` |
| `seclog.NewECSModel()` | `@timestamp` | `message` | `service.name` | Emits `event.*`, `user.*` and `log.level` |

```go
logger := seclog.NewLogger("my-app", seclog.WithModel(seclog.NewECSModel()))
logger.Log(seclog.ContextWithPrincipal(ctx, principal), event.AuthenticationLoginSuccess())

// {"@timestamp":"...","message":"User <account:johnsurname1> login successfully","service.name":"my-app","event.kind":"event","event.code":"authn_login_success","event.action":"user-login","event.category":["authentication"],"event.type":["access"],"event.outcome":"success","event.severity":1,"log.level":"INFO","user.name":"johnsurname1"}
```

The two vocabularies are not interchangeable, so a few `Fields` members are
meaningful for only one of them:

- `OWASPPort` and `OWASPGeo` are emitted only by the OWASP model;
- `SourceGeo` and `DestinationGeo` are emitted only by the ECS model.

```go
logger.LogWith(ctx, nil, seclog.Fields{
	SourceIP: "203.0.113.7",
	SourceGeo: seclog.GeoFields{
		CityName:       "Toronto",
		CountryISOCode: "CA",
		Location:       &seclog.GeoPoint{Latitude: 43.65, Longitude: -79.38},
	},
}, event.AuthenticationLoginFail())

// {"@timestamp":"...","message":"User <account:johnsurname1> login failed","service.name":"my-app","event.kind":"event","event.code":"authn_login_fail","event.action":"user-login","event.category":["authentication"],"event.type":["access"],"event.outcome":"failure","event.severity":2,"log.level":"WARN","user.name":"johnsurname1","source.ip":"203.0.113.7","source.geo.city_name":"Toronto","source.geo.country_iso_code":"CA","source.geo.location":{"lat":43.65,"lon":-79.38}}
```

Applications can support another schema by implementing `Model`, and optionally
`HandlerProvider` to supply the matching `slog.Handler`.

### Destinations and handlers

To write somewhere other than `os.Stdout`, use `WithWriter()`. The selected
model still builds the handler, so the output keeps its envelope:

```go
logger := seclog.NewLogger("my-app",
	seclog.WithModel(seclog.NewECSModel()),
	seclog.WithWriter(file), // still emits @timestamp and message
)
```

`WithHandler()` sets an existing handler, which is mainly useful for tests and
integrations. It keeps only the attributes that the model supplies, not the
output envelope, because the timestamp, the message and the level belong to the
handler: OWASP records lose `datetime` and `description`, and ECS records lose
`@timestamp` and `message` and regain `level`.

When the envelope must survive, compose the model's own handler with
`NewOWASPHandler()` or `NewECSHandler()`:

```go
logger := seclog.NewLogger("my-app",
	seclog.WithModel(seclog.NewECSModel()),
	seclog.WithHandler(myBufferingHandler(seclog.NewECSHandler(file))),
)
```

Records are emitted synchronously, so a blocked destination blocks the calling
goroutine. A service writing to a slow remote sink should inject a handler with
its own buffering and drop policy, paired with `WithErrorHandler()`.

### Field mapping

| `Fields` member | OWASP output | ECS output |
| --- | --- | --- |
| `TraceID` | `trace_id` | `trace.id` |
| `SpanID` | `span_id` | `span.id` |
| `TransactionID` | `transaction_id` | `transaction.id` |
| `UserAgent` | `useragent` | `user_agent.original` |
| `SourceIP` | `source_ip` | `source.ip` |
| `SourcePort` | `source_port` | `source.port` |
| `DestinationPort` | `destination_port` | `destination.port` |
| `HostIP` | `host_ip` | `host.ip` |
| `HostName` | `hostname` | `host.hostname` |
| `Protocol` | `protocol` | `network.protocol` |
| `OWASPPort` | `port` | omitted |
| `RequestURI` | `request_uri` | `url.original` |
| `RequestMethod` | `request_method` | `http.request.method` |
| `Region` | `region` | `cloud.region` |
| `OWASPGeo` | `geo` | omitted |
| `SourceGeo` | omitted | `source.geo.*` |
| `DestinationGeo` | omitted | `destination.geo.*` |
| `ServiceVersion` | `service_version` | `service.version` |
| `HTTPStatusCode` | `http_status_code` | `http.response.status_code` |

The principal maps to ECS as `user.name` (from `Account`, or from
`ServiceAccount` when `Account` is empty), `user.effective.name` (from
`ServiceAccount` when `Account` is set), `user.email` and `user.full_name`. It
is omitted when no principal is available, because `unknown` is an OWASP
convention and not a real user name.

`event.severity` uses this package's numeric convention: `INFO` is 1, `WARN` is
2, and `CRITICAL` is 3.

## Examples

Check `cmd/seclogexample` for examples of using this package.

## Contributing

Feel free to open issues or submit pull requests.

It is recommended to use [workshop](https://ubuntu.com/workshop) for local development with agents:

```bash
workshop launch
workshop shell dev
```
