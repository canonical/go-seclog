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

// Command seclogexample demonstrates the go-seclog API.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/canonical/go-seclog"
	"github.com/canonical/go-seclog/event"
)

func main() {
	ctx := context.Background()

	// Initializing:
	// Setup configures the package-level logger. It replaces the
	// configuration atomically, so it is safe to call while other
	// goroutines are logging.
	seclog.Setup("my-app",
		seclog.WithFields(seclog.Fields{
			HostIP: "10.1.1.1",
			Region: "us-east-1",
		}),
		seclog.WithModel(seclog.NewOWASPModel()),
	)

	// NewLogger creates a logger with its own, immutable configuration.
	customLogger := seclog.NewLogger("my-other-app",
		seclog.WithFields(seclog.Fields{
			HostIP: "10.2.3.4",
			Region: "us-east-2",
		}),
	)

	// Security events are always emitted at slog level INFO; their own
	// significance is reported in the `severity` field.
	seclog.Log(ctx, event.SystemStartup())
	customLogger.Log(ctx, event.SystemStartup())

	// A logger can also travel in the context: the package-level functions
	// emit with it instead of the package-level logger, so the code called
	// with this context logs as "my-other-app".
	customCtx := seclog.ContextWithLogger(ctx, customLogger)
	seclog.Log(customCtx, event.SystemStartup())

	// A nil logger discards the events, so an optional logger can be used
	// without a nil check.
	var optionalLogger *seclog.Logger
	optionalLogger.Log(ctx, event.SystemStartup()) // emits nothing

	// Using a principal:
	// Storing the actor of the events in the context.
	account := &seclog.Principal{Account: "my-username"}
	ctx = seclog.ContextWithPrincipal(ctx, account)

	seclog.Log(ctx, event.AuthenticationLoginSuccess())
	seclog.Log(ctx, event.AuthenticationPasswordChange())

	tokenID := "my-token"
	entitlements := []string{"read", "write"}
	seclog.Log(ctx, event.AuthenticationTokenCreated(entitlements...))
	seclog.Log(ctx, event.AuthenticationTokenRevoked(tokenID))

	// Some events take extra qualifiers, such as the attempt limit that
	// was reached or the reason why an account was locked.
	const maxAttempts = 3
	seclog.Log(ctx,
		event.AuthenticationLoginFail(),
		event.AuthenticationLoginFailMaxTries(maxAttempts),
		event.AuthenticationLoginLock(event.LoginLockReasonMaxRetries),
	)

	// LogWith emits events with a one-off principal, without storing it in
	// the context.
	anotherAccount := &seclog.Principal{Account: "another-username"}
	seclog.LogWith(ctx, anotherAccount, seclog.Fields{}, event.AuthorizationFail("database"))

	// Using fields:
	// Context fields override the non-zero default fields of the logger.
	ctx = seclog.ContextWithFields(ctx, seclog.Fields{
		OWASPPort:  1234,
		RequestURI: "/login",
		TraceID:    "b18794e8-5d0d-417c-b361-ba38e78411b4",
	})
	seclog.Log(ctx, event.SystemCrash("some-reason"))

	// Per-call fields override both the logger and the context fields.
	seclog.LogWith(ctx, nil, seclog.Fields{Protocol: "http"}, event.SystemCrash("some-other-reason"))

	// Several events can be emitted in one call; each one becomes its own
	// record, and all of them observe the same principal and fields.
	seclog.Log(ctx,
		event.UserCreated("new-user", "admin"),
		event.AuthorizationAdmin("user-create", "created new-user as admin"),
	)

	// Using the ECS model:
	// The same events are emitted with Elastic Common Schema field names.
	ecsLogger := seclog.NewLogger("my-app", seclog.WithModel(seclog.NewECSModel()))
	ecsLogger.Log(ctx, event.AuthenticationLoginSuccess())

	// A few fields belong to one vocabulary only: SourceGeo and
	// DestinationGeo are emitted by the ECS model, OWASPGeo by the OWASP
	// model.
	ecsLogger.LogWith(ctx, nil, seclog.Fields{
		SourceIP: "203.0.113.7",
		SourceGeo: seclog.GeoFields{
			CityName:       "Toronto",
			CountryISOCode: "CA",
			Location:       &seclog.GeoPoint{Latitude: 43.65, Longitude: -79.38},
		},
	}, event.AuthenticationLoginFail())

	// Choosing a destination:
	// WithWriter writes elsewhere while keeping the envelope of the model,
	// and WithErrorHandler reports the records the handler failed to emit,
	// as a lost record is a lost security event.
	var buffer bytes.Buffer
	bufferedLogger := seclog.NewLogger("my-app",
		seclog.WithWriter(&buffer),
		seclog.WithErrorHandler(func(err error) {
			fmt.Fprintf(os.Stderr, "seclog: security event lost: %v\n", err)
		}),
	)
	bufferedLogger.Log(ctx, event.SystemShutdown())
	fmt.Print(buffer.String())
}
