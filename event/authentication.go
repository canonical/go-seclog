// Copyright 2026 Canonical Ltd.

// Package event provides the constructors for the security events described
// by the OWASP Logging Cheat Sheet.
//
// Every constructor returns a seclog.EventFunc that is evaluated by the logger
// once the principal and the fields of the call have been resolved:
//
//	seclog.Log(ctx, event.AuthenticationLoginSuccess())
//
// Each event carries both its stable OWASP identity, used by the OWASP model,
// and its ECS classification, used by the ECS model. Applications may define
// their own constructors with the same signature.
package event

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/canonical/go-seclog"
)

// ECS event.category values used by this package.
const (
	categoryAuthentication = "authentication"
	categoryIAM            = "iam"
	categoryProcess        = "process"
	categoryHost           = "host"
)

// ECS event.type values used by this package.
const (
	typeAccess   = "access"
	typeAdmin    = "admin"
	typeChange   = "change"
	typeCreation = "creation"
	typeDeletion = "deletion"
	typeDenied   = "denied"
	typeEnd      = "end"
	typeError    = "error"
	typeStart    = "start"
)

// Shared package-level slices, so that events do not allocate on every log
// call.
var (
	authenticationCategory = []string{categoryAuthentication}
	iamCategory            = []string{categoryIAM}
	processCategory        = []string{categoryProcess}
	hostCategory           = []string{categoryHost}

	accessType   = []string{typeAccess}
	adminType    = []string{typeAdmin}
	changeType   = []string{typeChange}
	creationType = []string{typeCreation}
	deletionType = []string{typeDeletion}
	deniedType   = []string{typeDenied}
	endType      = []string{typeEnd}
	errorType    = []string{typeError}
	startType    = []string{typeStart}
)

// AuthenticationLoginSuccess generates authn_login_success[:userid]
//
// All login events should be recorded including success.
func AuthenticationLoginSuccess() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_login_success",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("User %s login successfully", principal),

			Kind:       seclog.KindEvent,
			Action:     "user-login",
			Categories: authenticationCategory,
			Types:      accessType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// AuthenticationLoginFail generates authn_login_fail[:userid]
//
// All login events should be recorded including failure.
func AuthenticationLoginFail() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_login_fail",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("User %s login failed", principal),

			Kind:       seclog.KindEvent,
			Action:     "user-login",
			Categories: authenticationCategory,
			Types:      accessType,
			Outcome:    seclog.OutcomeFailure,
		}
	}
}

// AuthenticationLoginFailMaxTries generates authn_login_fail_max_tries[:userid,maxattempts]
//
// All login events should be recorded including failure.
func AuthenticationLoginFailMaxTries(maxAttempts int) seclog.EventFunc {
	// Rendered once here instead of on every log call.
	maxAttemptsValue := strconv.Itoa(maxAttempts)
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_login_fail_max_tries",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal, maxAttemptsValue},
			Description: fmt.Sprintf("User %s reached the login fail limit of %s", principal, maxAttemptsValue),

			Kind:       seclog.KindEvent,
			Action:     "user-login-failure-limit",
			Categories: authenticationCategory,
			Types:      deniedType,
			Outcome:    seclog.OutcomeFailure,
		}
	}
}

// LoginLockReason is the reason for which an account was locked.
type LoginLockReason string

const (
	// LoginLockReasonMaxRetries is when the maximum number of retries was reached.
	LoginLockReasonMaxRetries LoginLockReason = "maxretries"
	// LoginLockReasonSuspicious is when suspicious activity was observed on the account.
	LoginLockReasonSuspicious LoginLockReason = "suspicious"
	// LoginLockReasonCustomer is when the customer requested their account be locked.
	LoginLockReasonCustomer LoginLockReason = "customer"
	// LoginLockReasonOther is any other reason.
	LoginLockReasonOther LoginLockReason = "other"
)

// AuthenticationLoginLock generates authn_login_lock[:userid,reason]
//
// When the feature exists to lock an account after x retries or other
// condition, the lock should be logged with relevant data.
func AuthenticationLoginLock(reason LoginLockReason) seclog.EventFunc {
	// Converted once here instead of on every log call.
	reasonValue := string(reason)
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_login_lock",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal, reasonValue},
			Description: fmt.Sprintf("User %s login locked because %s", principal, reasonValue),

			Kind:       seclog.KindEvent,
			Action:     "user-account-lock",
			Categories: iamCategory,
			Types:      changeType,
			Outcome:    seclog.OutcomeSuccess,
			Reason:     reasonValue,
		}
	}
}

// AuthenticationPasswordChange generates authn_password_change[:userid]
//
// Every password change should be logged, including the userid that it was for.
func AuthenticationPasswordChange() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_password_change",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("User %s has successfully changed their password", principal),

			Kind:       seclog.KindEvent,
			Action:     "user-password-change",
			Categories: iamCategory,
			Types:      changeType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// AuthenticationPasswordChangeFail generates authn_password_change_fail[:userid]
//
// An attempt to change a password that failed. May also trigger other events
// such as authn_login_lock.
func AuthenticationPasswordChangeFail() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_password_change_fail",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("User %s failed to change their password", principal),

			Kind:       seclog.KindEvent,
			Action:     "user-password-change",
			Categories: iamCategory,
			Types:      changeType,
			Outcome:    seclog.OutcomeFailure,
		}
	}
}

// AuthenticationTokenCreated generates authn_token_created[:userid,entitlement(s)]
//
// When a token is created for service access it should be recorded.
func AuthenticationTokenCreated(entitlements ...string) seclog.EventFunc {
	// Joined here, so the event does not retain the caller's slice.
	entitlementsStr := strings.Join(entitlements, ",")
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_token_created",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{principal, entitlementsStr},
			Description: fmt.Sprintf("A token has been created for %s with entitlements <%s>", principal, entitlementsStr),

			Kind:       seclog.KindEvent,
			Action:     "user-token-create",
			Categories: iamCategory,
			Types:      creationType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// AuthenticationTokenRevoked generates authn_token_revoked[:userid,tokenid]
//
// A token has been revoked for the given account.
func AuthenticationTokenRevoked(tokenID string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_token_revoked",
			Severity:    seclog.SeverityInfo,
			Qualifiers:  []string{principal, tokenID},
			Description: fmt.Sprintf("Token <id:%s> was revoked for user %s", tokenID, principal),

			Kind:       seclog.KindEvent,
			Action:     "user-token-revoke",
			Categories: iamCategory,
			Types:      deletionType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}

// AuthenticationTokenReuse generates authn_token_reuse[:userid,tokenid]
//
// A token has been reused for the given account.
func AuthenticationTokenReuse(tokenID string) seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_token_reuse",
			Severity:    seclog.SeverityCritical,
			Qualifiers:  []string{principal, tokenID},
			Description: fmt.Sprintf("User %s attempted to use token <id:%s>", principal, tokenID),

			Kind:       seclog.KindEvent,
			Action:     "user-token-reuse",
			Categories: authenticationCategory,
			Types:      deniedType,
			Outcome:    seclog.OutcomeFailure,
		}
	}
}

// AuthenticationTokenDelete generates authn_token_delete[:userid]
//
// When a token is deleted it should be recorded.
func AuthenticationTokenDelete() seclog.EventFunc {
	return func(ec seclog.EventContext) seclog.Event {
		principal := ec.Principal.String()
		return seclog.Event{
			Name:        "authn_token_delete",
			Severity:    seclog.SeverityWarn,
			Qualifiers:  []string{principal},
			Description: fmt.Sprintf("The token for user %s has been deleted", principal),

			Kind:       seclog.KindEvent,
			Action:     "user-token-delete",
			Categories: iamCategory,
			Types:      deletionType,
			Outcome:    seclog.OutcomeSuccess,
		}
	}
}
