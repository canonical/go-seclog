// Copyright 2026 Canonical Ltd.

package event

import (
	"fmt"

	"github.com/canonical/go-seclog"
)

// AuthorizationFail generates authz_fail[:userid,resource]
//
// An attempt was made to access a resource which was unauthorized.
func AuthorizationFail(resource string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
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
// The action argument is used verbatim as the ECS event.action, because the
// package cannot know which administrative operation was performed.
func AuthorizationAdmin(action string, details string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
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
