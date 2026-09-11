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

// AuthorizationFail generates authz_fail[:userid,resource]
//
// An attempt was made to access a resource which was unauthorized.
//
// If sanitization is enabled, resource is sanitized.
func AuthorizationFail(resource string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		resource := ec.Sanitize(resource)
		return seclog.Event{
			Name:        "authz_fail",
			Severity:    seclog.SeverityCritical,
			Qualifiers:  []string{principal, resource},
			Description: fmt.Sprintf("User %s attempted to access <resource:%s>", principal, resource),

			Kind:       seclog.KindEvent,
			Action:     "authorization-check",
			Categories: iamCategory,
			Types:      deniedType,
			Outcome:    seclog.OutcomeFailure,
		}
	}
}

// AuthorizationAdmin generates authz_admin[:userid,event]
//
// All activity by privileged users such as admin should be recorded.
//
// The action argument is used as the ECS event.action.
// If sanitization is enabled, action and details are sanitized.
func AuthorizationAdmin(action string, details string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		action := ec.Sanitize(action)
		details := ec.Sanitize(details)
		return seclog.Event{
			Name:        "authz_admin",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal, action},
			Description: fmt.Sprintf("Admin %s performed <event:%s>: %s", principal, action, details),

			Kind:       seclog.KindEvent,
			Action:     action,
			Categories: iamCategory,
			Types:      adminType,
			Outcome:    seclog.OutcomeUnknown,
		}
	}
}
