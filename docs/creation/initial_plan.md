# Rewriting zapseclog

> **Historical document.** This is the original design request that started the
> package, kept for context. It is not current: parts of it have since been
> superseded, most notably the ECS model, which it defers but which is now
> implemented. `implementation.md` is the effective specification.

I created a package called `zapseclog` for Security Event Logging using the zap logger.

Now `canonical` wants me to create a better Security Event Logging for the whole company, so I need to do some small tweaks.

## Changes

### Change to slog

The first core change is to remove the `zap` dependency and use `slog` instead.
This means that I would need to change how the core logging pattern:

- With `zap`, I as configuring it to be a JSON logger, with timestamp and level fields preset.
  - Now I need to configure `slog` to be a JSON logger, and perhaps add manually these fields when logging.
- With `zap`, unit tests used the `zap` logger with `zaptest`.
  - Now I need to configure `slog` in a way to be testable.

### More fields

Besides logging the necessary fields for each event, I also added the support for additional optional fields.
Now, I would like to rename it to `Field` (instead of OptionalFields or DefaultFields), and find a way for it to
be more easy to extend in the future. For example, to add one more field, I need to change the String() and merge() method.
Perhaps I would need to find out a better way to merge the fields together.

### Not compromise speed

`zap` was fast, and I don't want the change to `slog` to compromise speed. So I don't want to add extra overhead (e.g. a lot of memory allocation, reflections).

### Refactor events

I enjoyed the way I structured the events, but writing a log is still somewhat verbose:

```go
zapseclog.Log(zapseclog.EventAuthenticationXXXX(...))
```

So perhaps I would move the events to a `event` package (possibly github.com/go-seclog/event) and rename the methods:

```go
seclog.Log(event.AuthenticationXXXX(...))
```

### Be ready to extend beyond OWASP

So I made the core logging to follow OWASP guidelines for logging.
But now I need to *be ready* to support ECS (https://www.elastic.co/docs/reference/ecs/ecs-field-reference) and/or beyond.
So I don't want to implement ECS right now, but I need to be ready for it.

This means that perhaps I would need to change some setup methods, for example:

```go
// instead of
zapseclog.UseAppID("my-app-id")
zapseclog.UseDefaultFields(fields)
// or
logger := zapseclog.NewLogger("my-app-id", &zapseclog.OptionalFields{})

// I would like to try something like
seclog.Setup("my-app-id",
	seclog.WithFields(fields),
	seclog.WithModel(seclog.OWASPLogger),
)
// or
logger := seclog.NewLogger("my-app-id",
	seclog.WithFields(fields),
	seclog.WithModel(seclog.OWASPLogger),
)
```

IMPORTANT: currently I also push some information to context, so I don't know how this would conflict name-wise.
Because I use `.WithX` methods for context manipulation (e.g. `ctx := zapseclog.WithPrincipal(ctx, principal)`).
So I would need to separate context manipulation methods from options pattern for logger setup.

## Actions

So first, consider this, and follow the current `zapseclog` implementation in `_old` folder, or check `github.com/canonical/zapseclog` (but it is private).

Consider the tweaks, and then create a spec `implementation.md` in the root of this package on what would you do. I will check it, make suggestions and changes, and after I authorize, you will implement it.
