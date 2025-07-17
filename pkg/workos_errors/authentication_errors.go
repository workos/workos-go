package workos_errors

import (
	"errors"
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

// AuthenticationFactor represents an MFA factor
type AuthenticationFactor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Organization represents an organization in selection error
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// User represents a user in authentication errors
type User struct {
	Object            string `json:"object"`
	ID                string `json:"id"`
	Email             string `json:"email"`
	FirstName         string `json:"first_name"`
	LastName          string `json:"last_name"`
	EmailVerified     bool   `json:"email_verified"`
	ProfilePictureURL string `json:"profile_picture_url"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

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
	Code                       string         `json:"code"`
	Message                    string         `json:"message"`
	User                       User           `json:"user"`
	Organizations              []Organization `json:"organizations"`
	PendingAuthenticationToken string         `json:"pending_authentication_token"`
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

// Type checking functions
func IsEmailVerificationRequired(err error) bool {
	var emailErr *EmailVerificationRequiredError
	return errors.As(err, &emailErr)
}

func IsMFAEnrollment(err error) bool {
	var mfaErr *MFAEnrollmentError
	return errors.As(err, &mfaErr)
}

func IsMFAChallenge(err error) bool {
	var mfaErr *MFAChallengeError
	return errors.As(err, &mfaErr)
}

func IsOrganizationSelectionRequired(err error) bool {
	var orgErr *OrganizationSelectionRequiredError
	return errors.As(err, &orgErr)
}

func IsSSORequired(err error) bool {
	var ssoErr *SSORequiredError
	return errors.As(err, &ssoErr)
}

func IsOrganizationAuthenticationMethodsRequired(err error) bool {
	var orgAuthErr *OrganizationAuthenticationMethodsRequiredError
	return errors.As(err, &orgAuthErr)
}

// Type assertion functions
func AsEmailVerificationRequired(err error) (*EmailVerificationRequiredError, bool) {
	var emailErr *EmailVerificationRequiredError
	if errors.As(err, &emailErr) {
		return emailErr, true
	}
	return nil, false
}

func AsMFAEnrollment(err error) (*MFAEnrollmentError, bool) {
	var mfaErr *MFAEnrollmentError
	if errors.As(err, &mfaErr) {
		return mfaErr, true
	}
	return nil, false
}

func AsMFAChallenge(err error) (*MFAChallengeError, bool) {
	var mfaErr *MFAChallengeError
	if errors.As(err, &mfaErr) {
		return mfaErr, true
	}
	return nil, false
}

func AsOrganizationSelectionRequired(err error) (*OrganizationSelectionRequiredError, bool) {
	var orgErr *OrganizationSelectionRequiredError
	if errors.As(err, &orgErr) {
		return orgErr, true
	}
	return nil, false
}

func AsSSORequired(err error) (*SSORequiredError, bool) {
	var ssoErr *SSORequiredError
	if errors.As(err, &ssoErr) {
		return ssoErr, true
	}
	return nil, false
}

func AsOrganizationAuthenticationMethodsRequired(err error) (*OrganizationAuthenticationMethodsRequiredError, bool) {
	var orgAuthErr *OrganizationAuthenticationMethodsRequiredError
	if errors.As(err, &orgAuthErr) {
		return orgAuthErr, true
	}
	return nil, false
}
