# go-seclog implementation review

Review date: 2026-08-31

## Verdict

The library is useful and its main architecture is sound. The public API is
small, the OWASP compatibility layer is understandable, ECS is separated
cleanly, configuration is safe for concurrent use, and the implementation is
fast enough for a service handling hundreds of requests per second.

I would still address the handler error policy and the zero-coordinate ECS bug
before calling the API stable. The retained variadic arguments, handler
integration contract, and a few documentation inconsistencies should also be
resolved before broad adoption.

## Findings

### 1. Handler failures silently lose security events

**Priority: high**

`Logger.Log` discards the error returned by `slog.Handler.Handle`
(`logger.go:165`). A full disk, closed pipe, failed network sink, or custom
handler error therefore looks exactly like successful security logging to the
application. This is especially risky for a package whose purpose is audit and
security evidence.

The standard `slog.Logger` also does not return handler errors, but this package
calls the handler directly and can define a stronger reliability contract.
Before the API is stable, prefer one of these approaches:

1. Make `Log` and `LogWith` return an error. Existing call statements can still
   ignore a returned value. For calls containing several events, attempt all
   records and return `errors.Join` of the failures.
2. If returning errors is intentionally rejected, add an explicit required or
   configurable error callback and document exactly when it runs.

Do not add an implicit unbounded asynchronous queue. It would trade visible
backpressure for memory growth or silent loss. Applications that need
asynchronous output should provide a bounded handler with an explicit
backpressure, drop, and metrics policy.

### 2. Valid ECS locations on the equator or prime meridian are omitted

**Priority: high**

`appendECSGeo` emits `geo.location` only when both coordinates are non-zero
(`ecs.go:171`). Zero is a valid latitude and a valid longitude, so locations on
the equator or prime meridian cannot be represented. A location such as
`(51.4779, 0)` is silently dropped.

The current value type cannot distinguish "not supplied" from a supplied zero.
Change `GeoFields.Location` to `*GeoPoint`, or add an explicit presence field,
before compatibility constraints make this harder. Emit the location whenever
it is present, then validate latitude and longitude ranges separately if
validation is desired.

### 3. Deferred event constructors retain caller-owned slices

**Priority: medium**

`AuthenticationTokenCreated`, `UserCreated`, and `UserUpdated` capture their
variadic slice and join it only when the event is logged
(`event/authentication.go:210-213`, `event/user.go:17-20`, and
`event/user.go:40-43`). Mutating the original slice after constructing an
`EventFunc` changes future records and can introduce a data race when a
reusable event is logged concurrently.

Join the values before returning the closure and capture the resulting string.
That makes the constructor snapshot its input and moves the `strings.Join`
allocation out of the logging hot path.

The package-level category and type slices have a related, lower-risk issue:
every generated `Event` exposes shared mutable slices. The `Model` contract
forbids mutation, which protects normal use, but an application that evaluates
an event directly can still corrupt classifications for later events. Keep
this documented or represent built-in classifications with immutable internal
values.

### 4. `WithHandler` weakens the selected model's output contract

**Priority: medium**

The model-specific envelope is implemented by each built-in JSON handler, not
by `Model.AppendAttrs`. Supplying an ordinary existing handler through
`WithHandler` therefore changes:

- OWASP `datetime` and `description` back to handler-specific keys, commonly
  `time` and `msg`;
- ECS `@timestamp` and `message` back to handler-specific keys and may restore
  the regular slog `level`.

The code comments mention that a custom handler owns its key configuration
(`logger.go:54-60`), but the README also presents `WithHandler` as an
integration mechanism. A user can reasonably select `ECSModel`, provide the
service's existing handler, and expect ECS output.

Clarify that `WithHandler` preserves only model attributes, not the complete
OWASP or ECS envelope. Expose direct, typed handler constructors such as
`NewOWASPHandler` and `NewECSHandler`, with handler options where appropriate,
instead of requiring the awkward
`OWASPModel.(HandlerProvider).NewHandler(writer)` assertion. If integration
with arbitrary existing handlers is a goal, define the limits explicitly;
generic slog handlers cannot be forced to use a particular serialized
envelope.

### 5. Empty application IDs produce weak or missing identity

**Priority: medium**

`NewLogger` stores `appID` without validation (`logger.go:89-101`). OWASP emits
an empty `appid`, while ECS omits `service.name` because its append helper
suppresses empty strings. This is likely to be accidental and makes records
harder to route and attribute.

Because `NewLogger` deliberately has no error return, normalize an empty
application ID to `unknown`, panic with a clear programmer-error message, or
add a separately validated constructor. Normalizing to `unknown` is consistent
with the package-level logger before `Setup`.

### 6. `LogWith` principal documentation contradicts its behavior

**Priority: low**

The `LogWith` godoc says the supplied principal replaces any principal in the
context (`logger.go:172`), but a nil principal leaves the context principal in
place (`logger.go:181` and `principal.go:82-87`). The tests intentionally
assert the latter behavior.

Document the precise rule: a non-nil principal replaces the context principal,
nil preserves it, and `&Principal{}` can explicitly produce an unknown/omitted
principal. This matters because incorrect actor attribution is worse than a
minor logging-format discrepancy.

### 7. Built-in model values are exported mutable variables

**Priority: low**

`OWASPModel` and `ECSModel` are exported package variables holding interfaces
(`owasp.go:34`, `ecs.go:41`). Any consumer can assign to them, creating global
behavior changes, data races, or a nil-model panic in unrelated loggers. This
works against the otherwise strong immutable-configuration design.

Consider exported concrete model types or constructor functions before v1. If
the variables remain, explicitly document that consumers must treat them as
read-only.

## Performance

### Measurements

Benchmarks were run on Linux/amd64 with an Intel Core Ultra 7 268V and Go
1.26.2. JSON was fully encoded but written to a discard writer, so the figures
measure package and handler CPU/allocation cost, not stdout, filesystem, or
network latency. Values below are approximate medians across five runs.

| Path | Time/op | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| Existing synthetic OWASP event, no fields | 1.2 us | 1,056 | 3 |
| Existing synthetic OWASP event, contextual fields | 1.9 us | 1,248 | 6 |
| Real OWASP login event with typical context | 1.4 us | 1,329 | 8 |
| Real ECS login event with typical context | 3.7 us | 2,011 | 23 |
| OWASP `LogWith` with principal and fields | 1.9 us | 2,002 | 12 |
| Principal and field context enrichment only | 0.38 us | 672 | 4 |
| Disabled handler | 2.1 ns | 0 | 0 |
| Equivalent legacy Zap OWASP path | 1.2 us | 1,731 | 10 |

The OWASP path is roughly 10-15% slower than the comparable legacy Zap path on
this machine, but allocates about 23% fewer bytes and two fewer objects. The
disabled path successfully avoids event construction and allocation.

At 1,000 security records per second, the measured real OWASP path accounts for
about 1.4 ms of CPU time and 1.3 MB of short-lived allocation per second. ECS
accounts for about 3.7 ms and 2.0 MB per second. This is comfortably within the
budget of an ordinary service. At hundreds of records per second, package
overhead is unlikely to be observable compared with request processing,
transport, and storage.

The real operational limit is the synchronous handler and destination.
`slog.JSONHandler` serializes writes, and a blocked stdout collector or network
sink blocks request goroutines. This behavior is preferable to silently
dropping security events, but it needs to be stated in the README. Services
with slow remote sinks should inject a handler whose bounded buffering and
failure policy match their reliability requirements.

### Useful optimizations

Optimization is not required to support hundreds of requests per second.
These changes are worthwhile if reducing garbage at higher rates becomes a
goal:

1. Avoid the two temporary context values in `LogWith`. Resolve its principal
   and merge its fields directly, then call a shared unexported emission
   method also used by `Log`. The measurement attributes exactly 672 bytes and
   four allocations to context enrichment in the typical case.
2. Right-size the attribute buffer by model. The unconditional capacity of 24
   (`logger.go:17-20`, `logger.go:151`) is approximately a 960-byte backing
   array on this platform, even for OWASP's four required attributes. A small
   built-in model capacity hint can use about 8 for typical OWASP records and a
   larger value for ECS without reflection.
3. Build `Principal.String` with one `strings.Builder`. It currently creates
   intermediate `"key:"+value` strings and then joins them.
4. Precompute constructor arguments that do not depend on `EventContext`, as
   described in finding 3.
5. Add durable benchmarks for real built-in events, ECS, `LogWith`, context
   creation, disabled handlers, and parallel calls. The current
   `BenchmarkLog` uses the synthetic `principalEvent` and does not perform the
   legacy comparison required by `implementation.md`.

Do not replace the explicit `Fields.merge` or model mappings with reflection.
They are predictable, type-safe, allocation-free, and appropriate for this
field count. If the field list grows substantially, generate those explicit
functions rather than interpreting struct tags at runtime.

## Specification and plan comparison

The implementation follows nearly all material decisions in
`implementation.md`: package layout, closed fields, merge precedence, deferred
events, immutable loggers, atomic setup, model separation, OWASP compatibility,
ECS classification, tests, and Go 1.25 targeting are all present.

The remaining mismatches or stale points are:

- The specified logging pipeline resolves context before checking
  `Handler.Enabled` (`implementation.md:724-733`); the code checks first. The
  implementation is better because a disabled logger remains allocation-free,
  so update the specification rather than the code.
- The specification says invalid nil custom configuration is a programmer
  error (`implementation.md:585-588`), while `WithModel(nil)` and
  `WithHandler(nil)` are silently ignored and tested as supported behavior.
  Pick one contract and make the spec, godoc, and tests agree.
- The `Fields` mapping table omits `DestinationPort`, although the struct,
  implementation, and README support it. Add the missing row.
- The required benchmark comparison with the legacy package
  (`implementation.md:829-835`) is not represented by a durable benchmark.
- The specification's zero-value rule directly causes the invalid
  zero-coordinate behavior. It needs a location-specific presence exception.

`plan.md` is no longer sufficient as a project plan. It is the original design
request, says ECS should not yet be implemented (`plan.md:48`), and ends by
asking for `implementation.md` to be written and approved. ECS has since been
implemented, and `implementation.md` became the effective specification.
Rename or label `plan.md` as historical input, or replace it with a short
current roadmap containing the release blockers and post-v1 work. Keeping two
apparently current documents with contradictory scope will confuse future
contributors.

## Code organization and tests

The current file and package split is appropriate. `logger`, fields,
principal, models, and event constructors have separate responsibilities, and
the root/event package boundary avoids an import cycle while allowing custom
events. Further package fragmentation would make this small library harder to
navigate without adding meaningful isolation.

The tests are broad and readable, exercise concurrency under the race
detector, and cover the exported behavior well. One style issue remains:
constructor behavior is split between each `TestConstructor`,
`TestECSClassification`, and `TestOWASPEventValue`. This deviates from the
repository test guideline of keeping all cases for one function under one
test. Consolidating each constructor's identity, ECS classification, and
format edge cases would remove duplicate evaluation while preserving the
useful table-driven structure.

The best modularization change is internal, not another package: extract one
shared resolved-event emission method for `Log` and `LogWith`. It would retain
a single logging path while removing convenience-method context allocations.

## Recommended order

1. Define handler failure reporting.
2. Make `GeoPoint` presence explicit and support zero coordinates.
3. Snapshot variadic event arguments at construction time.
4. Clarify handler integration, application ID, and nil-principal contracts.
5. Expand durable benchmarks and then optimize `LogWith`, attribute capacity,
   and principal rendering against explicit allocation budgets.
6. Update `implementation.md` and replace or mark `plan.md` as historical.
