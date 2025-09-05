package workos_errors

import (
	"github.com/workos/workos-go/v5/pkg/common"
)

// Authentication error code constants
const (
	EmailVerificationRequiredCode                 = "email_verification_required"
	MFAEnrollmentCode                             = "mfa_enrollment"
	MFAChallengeCode                              = "mfa_challenge"
	OrganizationSelectionRequiredCode             = "organization_selection_required"
	SSORequiredCode                               = "sso_required"
	OrganizationAuthenticationMethodsRequiredCode = "organization_authentication_methods_required"
)

// FactorType represents the type of Authentication Factor
type FactorType string

// Constants that enumerate the available Types (matching mfa.FactorType)
const (
	SMS  FactorType = "sms"
	TOTP FactorType = "totp"
)

// AuthenticationFactor represents an MFA factor
type AuthenticationFactor struct {
	ID   string     `json:"id"`
	Type FactorType `json:"type"`
}

// PendingAuthenticationOrganizationInfo represents an organization in selection error
type PendingAuthenticationOrganizationInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// User is an alias for common.User to maintain consistency
type User = common.User

// EmailVerificationRequiredError occurs when a user with unverified email attempts authentication
type EmailVerificationRequiredError struct {
	HTTPError
	Code                       string `json:"code"`
	Message                    string `json:"message"`
	Email                      string `json:"email"`
	EmailVerificationID        string `json:"email_verification_id"`
	PendingAuthenticationToken string `json:"pending_authentication_token"`
}

func (e EmailVerificationRequiredError) Error() string {
	return e.HTTPError.Error()
}

// MFAEnrollmentError occurs when a user needs to enroll in MFA
type MFAEnrollmentError struct {
	HTTPError
	Code                       string `json:"code"`
	Message                    string `json:"message"`
	User                       User   `json:"user"`
	PendingAuthenticationToken string `json:"pending_authentication_token"`
}

func (e MFAEnrollmentError) Error() string {
	return e.HTTPError.Error()
}

// MFAChallengeError occurs when a user needs to complete MFA challenge
type MFAChallengeError struct {
	HTTPError
	Code                       string                 `json:"code"`
	Message                    string                 `json:"message"`
	User                       User                   `json:"user"`
	AuthenticationFactors      []AuthenticationFactor `json:"authentication_factors"`
	PendingAuthenticationToken string                 `json:"pending_authentication_token"`
}

func (e MFAChallengeError) Error() string {
	return e.HTTPError.Error()
}

// OrganizationSelectionRequiredError occurs when user must choose an organization
type OrganizationSelectionRequiredError struct {
	HTTPError
	Code                       string                                  `json:"code"`
	Message                    string                                  `json:"message"`
	User                       User                                    `json:"user"`
	Organizations              []PendingAuthenticationOrganizationInfo `json:"organizations"`
	PendingAuthenticationToken string                                  `json:"pending_authentication_token"`
}

func (e OrganizationSelectionRequiredError) Error() string {
	return e.HTTPError.Error()
}

// SSORequiredError occurs when user must authenticate via SSO
type SSORequiredError struct {
	HTTPError
	ErrorCode                  string   `json:"error"`
	ErrorDescription           string   `json:"error_description"`
	Email                      string   `json:"email"`
	ConnectionIDs              []string `json:"connection_ids"`
	PendingAuthenticationToken string   `json:"pending_authentication_token"`
}

func (e SSORequiredError) Error() string {
	return e.HTTPError.Error()
}

// OrganizationAuthenticationMethodsRequiredError occurs when org restricts auth methods
type OrganizationAuthenticationMethodsRequiredError struct {
	HTTPError
	ErrorCode                  string          `json:"error"`
	ErrorDescription           string          `json:"error_description"`
	Email                      string          `json:"email"`
	SSOConnectionIDs           []string        `json:"sso_connection_ids"`
	AuthMethods                map[string]bool `json:"auth_methods"`
	PendingAuthenticationToken string          `json:"pending_authentication_token"`
}

func (e OrganizationAuthenticationMethodsRequiredError) Error() string {
	return e.HTTPError.Error()
}
