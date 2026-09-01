// Copyright 2026 Canonical Ltd.

// Package seclog provides Security Event Logging on top of the standard
// library log/slog.
//
// It emits the security events recommended by the OWASP Logging Cheat Sheet,
// and each event can be emitted in either supported model: the OWASP field
// names or the Elastic Common Schema ones. The event constructors live in
// github.com/canonical/go-seclog/event.
//
// # Getting started
//
// Configure the package-level logger once, then log events with the
// constructors:
//
//	seclog.Setup("my-app",
//		seclog.WithFields(seclog.Fields{Region: "us-east-1"}),
//		seclog.WithModel(seclog.NewOWASPModel()),
//	)
//
//	ctx = seclog.ContextWithPrincipal(ctx, &seclog.Principal{Account: "user1"})
//	seclog.Log(ctx, event.AuthenticationLoginSuccess())
//
// Use NewLogger instead when the process needs more than one application
// identity or configuration:
//
//	logger := seclog.NewLogger("my-other-app", seclog.WithModel(seclog.NewECSModel()))
//	logger.Log(ctx, event.SystemStartup())
//
// A one-off principal and extra fields can be given per call, and several
// events can share one call:
//
//	seclog.LogWith(ctx, &seclog.Principal{Account: "user2"},
//		seclog.Fields{RequestURI: "/login", SourceIP: "203.0.113.7"},
//		event.AuthenticationLoginFail(),
//		event.AuthenticationLoginLock(event.LoginLockReasonMaxRetries),
//	)
//
// # Layers
//
// An event constructor owns the identity, severity and wording of an event; a
// Model owns the output field names and structure; the Logger resolves the
// context and emits one slog record per event. The same event therefore
// renders differently under each model:
//
//	seclog.Log(ctx, event.AuthenticationLoginSuccess())
//
//	// OWASP: {"datetime":"...","description":"User <account:user1> login successfully",
//	//         "appid":"my-app","event":"authn_login_success:<account:user1>","severity":"INFO",...}
//	// ECS:   {"@timestamp":"...","message":"User <account:user1> login successfully",
//	//         "service.name":"my-app","event.code":"authn_login_success","user.name":"user1",...}
//
// Records are always emitted at slog.LevelInfo, and the security significance
// of the event is reported by the model instead, so that critical security
// events are not mixed with critical system events by level.
//
// The output envelope, meaning the timestamp, message and level keys, belongs
// to the slog handler rather than to the Model. WithWriter keeps the handler
// of the selected model; WithHandler replaces it, and the given handler keeps
// its own keys:
//
//	seclog.NewLogger("my-app", seclog.WithWriter(file))          // keeps datetime and description
//	seclog.NewLogger("my-app", seclog.WithHandler(otherHandler)) // keeps the keys of otherHandler
//
// # Data policy
//
// Never pass secrets, credentials, access tokens or sensitive personal data to
// this package, and prefer identifiers over the values they identify: event
// constructors take a token ID, never a token.
package seclog
