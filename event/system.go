// Copyright 2026 Canonical Ltd.

package event

import (
	"fmt"

	"github.com/canonical/go-seclog"
)

// SystemStartup generates sys_startup:[userid]
//
// When a system is first started it can be valuable to log the startup, even
// if the system is serverless or a container, especially if possible to log
// the user that initiated the system.
func SystemStartup() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "sys_startup",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("User %s spawned a new instance", principal),

			Kind:       seclog.KindEvent,
			Action:     "system-start",
			Categories: processCategory,
			Types:      startType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// SystemShutdown generates sys_shutdown:[userid]
//
// Captures when a system or service is stopped, intentionally or not, as an
// unplanned shutdown can indicate a failure, a misconfiguration or an attack.
func SystemShutdown() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "sys_shutdown",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("User %s stopped this instance", principal),

			Kind:       seclog.KindEvent,
			Action:     "system-stop",
			Categories: processCategory,
			Types:      endType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// SystemRestart generates sys_restart:[userid]
//
// When a system is restarted it can be valuable to log the event, even if the
// system is serverless or a container, especially if possible to log the user
// that initiated the system.
func SystemRestart() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "sys_restart",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("User %s initiated a restart", principal),

			Kind:       seclog.KindEvent,
			Action:     "system-restart",
			Categories: processCategory,
			Types:      changeType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// SystemCrash generates sys_crash[:reason]
//
// If possible to catch an unstable condition resulting in the crash of a
// system, logging that event could be helpful, especially if the event is
// triggered by an attack.
//
// This is the only event with no principal, as a crash has no actor.
func SystemCrash(reason string) seclog.EventFunc {
	// Nothing in this event depends on the EventContext, so it is built
	// once here instead of on every log call.
	event := seclog.Event{
		Name:        "sys_crash",
		Severity:    seclog.SeverityWarn,
		Qualifiers:  []string{reason},
		Description: fmt.Sprintf("Instance crashed with <reason:%s>", reason),

		Kind:       seclog.KindEvent,
		Action:     "system-crash",
		Categories: processCategory,
		Types:      errorType,
		Outcome:    seclog.OutcomeFailure,
		Reason:     reason,
	}
	return func(seclog.EventContext) seclog.Event {
		return event
	}
}

// SystemMonitoringDisabled generates sys_monitor_disabled:[userid,monitor]
//
// If your systems contain agents responsible for file integrity, resources,
// logging, virus, etc. it is especially valuable to know if they are halted
// and by whom.
func SystemMonitoringDisabled(monitor string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "sys_monitor_disabled",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal, monitor},
			Description: fmt.Sprintf("User %s disabled <monitor:%s>", principal, monitor),

			Kind:       seclog.KindEvent,
			Action:     "monitoring-disable",
			Categories: hostCategory,
			Types:      changeType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}
