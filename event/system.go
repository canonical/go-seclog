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
// If sanitization is enabled, reason is sanitized.
func SystemCrash(reason string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		reason := ec.Sanitize(reason)
		return seclog.Event{
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
	}
}

// SystemMonitoringDisabled generates sys_monitor_disabled:[userid,monitor]
//
// If sanitization is enabled, monitor is sanitized.
func SystemMonitoringDisabled(monitor string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		monitor := ec.Sanitize(monitor)
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
