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
	"slices"
	"strings"

	"github.com/canonical/go-seclog"
)

// UserCreated generates user_created:[userid,newuserid,attributes[one,two,three]]
//
// If sanitization is enabled, newUserID and attributes are sanitized.
func UserCreated(newUserID string, attributes ...string) seclog.EventFunc {
	attributes = slices.Clone(attributes)
	attributesStr := strings.Join(attributes, ",")
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		newUserID := ec.Sanitize(newUserID)
		attributesStr := sanitizeJoin(ec, attributesStr, attributes)
		return seclog.Event{
			Name:        "user_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{principal, newUserID, attributesStr},
			Description: fmt.Sprintf("User %s created <user:%s> with <attributes:%s>", principal, newUserID, attributesStr),

			Kind:       seclog.KindEvent,
			Action:     "user-create",
			Categories: iamCategory,
			Types:      creationType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// UserUpdated generates user_updated:[userid,onuserid,attributes[one,two,three]]
//
// If sanitization is enabled, onUserID and attributes are sanitized.
func UserUpdated(onUserID string, attributes ...string) seclog.EventFunc {
	attributes = slices.Clone(attributes)
	attributesStr := strings.Join(attributes, ",")
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		onUserID := ec.Sanitize(onUserID)
		attributesStr := sanitizeJoin(ec, attributesStr, attributes)
		return seclog.Event{
			Name:        "user_updated",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{principal, onUserID, attributesStr},
			Description: fmt.Sprintf("User %s updated <user:%s> with <attributes:%s>", principal, onUserID, attributesStr),

			Kind:       seclog.KindEvent,
			Action:     "user-update",
			Categories: iamCategory,
			Types:      changeType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}
