// @oagen-ignore-file

package workos

import "fmt"

// APIError represents an error returned by the WorkOS API.
type APIError struct {
	StatusCode int    `json:"-"`
	RequestID  string `json:"-"`
	RetryAfter int    `json:"-"`
	RawBody    string `json:"-"`

	// Code is the error code from responses using the {"code": ..., "message": ...} format.
	Code string `json:"code"`
	// Message is the human-readable error message.
	Message string `json:"message"`
	// ErrorCode is the error identifier from responses using the {"error": ..., "error_description": ...} format (e.g. "invalid_client", "sso_required").
	ErrorCode string `json:"error"`
	// ErrorDescription is the human-readable description from OAuth-style error responses.
	ErrorDescription string `json:"error_description"`
	// Errors is a list of error strings returned by the API.
	Errors []string `json:"errors,omitempty"`
	// FieldErrors is a list of field-level validation errors.
	FieldErrors []FieldError `json:"-"`

	// PendingAuthenticationToken is a token for continuing an authentication flow that requires additional steps.
	PendingAuthenticationToken string `json:"pending_authentication_token,omitempty"`
	// EmailVerificationID is the ID of the pending email verification.
	EmailVerificationID string `json:"email_verification_id,omitempty"`
}

// FieldError represents a field-level validation error.
type FieldError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" && e.ErrorCode != "" {
		msg = e.ErrorCode
		if e.ErrorDescription != "" {
			msg += " " + e.ErrorDescription
		}
	}
	// When both Message and ErrorCode are empty (e.g., non-JSON 5xx responses),
	// include a truncated snippet of the raw body so users can diagnose the issue.
	if msg == "" && e.RawBody != "" {
		body := e.RawBody
		if len(body) > 200 {
			body = body[:200] + "..."
		}
		msg = body
	}
	base := fmt.Sprintf("workos: %d %s: %s (request_id: %s)", e.StatusCode, e.code(), msg, e.RequestID)
	if e.PendingAuthenticationToken != "" {
		base += fmt.Sprintf(", pending_authentication_token: %q", e.PendingAuthenticationToken)
	}
	if e.EmailVerificationID != "" {
		base += fmt.Sprintf(", email_verification_id: %q", e.EmailVerificationID)
	}
	return base
}

// code returns the best available error code identifier.
func (e *APIError) code() string {
	if e.Code != "" {
		return e.Code
	}
	return e.ErrorCode
}

// AuthenticationError represents 401 authentication errors.
type AuthenticationError struct {
	*APIError
}

func (e *AuthenticationError) Error() string { return e.APIError.Error() }
func (e *AuthenticationError) Unwrap() error { return e.APIError }

// NotFoundError represents 404 not found errors.
type NotFoundError struct {
	*APIError
}

func (e *NotFoundError) Error() string { return e.APIError.Error() }
func (e *NotFoundError) Unwrap() error { return e.APIError }

// UnprocessableEntityError represents 422 validation errors.
type UnprocessableEntityError struct {
	*APIError
}

func (e *UnprocessableEntityError) Error() string { return e.APIError.Error() }
func (e *UnprocessableEntityError) Unwrap() error { return e.APIError }

// RateLimitExceededError represents 429 rate limit errors.
type RateLimitExceededError struct {
	*APIError
}

func (e *RateLimitExceededError) Error() string { return e.APIError.Error() }
func (e *RateLimitExceededError) Unwrap() error { return e.APIError }

// ServerError represents 5xx server errors.
type ServerError struct {
	*APIError
}

func (e *ServerError) Error() string { return e.APIError.Error() }
func (e *ServerError) Unwrap() error { return e.APIError }

// NetworkError represents a connection failure.
type NetworkError struct {
	Err error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("workos: network error: %v", e.Err)
}

func (e *NetworkError) Unwrap() error { return e.Err }

// Authentication error code constants.
const (
	EmailVerificationRequiredCode                 = "email_verification_required"
	MFAEnrollmentCode                             = "mfa_enrollment"
	MFAChallengeCode                              = "mfa_challenge"
	OrganizationSelectionRequiredCode             = "organization_selection_required"
	SSORequiredCode                               = "sso_required"
	OrganizationAuthenticationMethodsRequiredCode = "organization_authentication_methods_required"
)

// PendingAuthenticationOrganization represents an organization in an organization selection error.
type PendingAuthenticationOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// EmailVerificationRequiredError occurs when a user with an unverified email attempts authentication.
type EmailVerificationRequiredError struct {
	*APIError
	Email string `json:"email"`
}

func (e *EmailVerificationRequiredError) Error() string { return e.APIError.Error() }
func (e *EmailVerificationRequiredError) Unwrap() error { return e.APIError }

// MFAEnrollmentError occurs when a user needs to enroll in MFA.
type MFAEnrollmentError struct {
	*APIError
	User User `json:"user"`
}

func (e *MFAEnrollmentError) Error() string { return e.APIError.Error() }
func (e *MFAEnrollmentError) Unwrap() error { return e.APIError }

// MFAChallengeError occurs when a user needs to complete an MFA challenge.
type MFAChallengeError struct {
	*APIError
	User                  User                   `json:"user"`
	AuthenticationFactors []AuthenticationFactor `json:"authentication_factors"`
}

func (e *MFAChallengeError) Error() string { return e.APIError.Error() }
func (e *MFAChallengeError) Unwrap() error { return e.APIError }

// OrganizationSelectionRequiredError occurs when a user must choose an organization.
type OrganizationSelectionRequiredError struct {
	*APIError
	User          User                                `json:"user"`
	Organizations []PendingAuthenticationOrganization `json:"organizations"`
}

func (e *OrganizationSelectionRequiredError) Error() string { return e.APIError.Error() }
func (e *OrganizationSelectionRequiredError) Unwrap() error { return e.APIError }

// SSORequiredError occurs when a user must authenticate via SSO.
type SSORequiredError struct {
	*APIError
	Email         string   `json:"email"`
	ConnectionIDs []string `json:"connection_ids"`
}

func (e *SSORequiredError) Error() string { return e.APIError.Error() }
func (e *SSORequiredError) Unwrap() error { return e.APIError }

// OrganizationAuthenticationMethodsRequiredError occurs when an organization restricts auth methods.
type OrganizationAuthenticationMethodsRequiredError struct {
	*APIError
	Email            string          `json:"email"`
	SSOConnectionIDs []string        `json:"sso_connection_ids"`
	AuthMethods      map[string]bool `json:"auth_methods"`
}

func (e *OrganizationAuthenticationMethodsRequiredError) Error() string {
	return e.APIError.Error()
}
func (e *OrganizationAuthenticationMethodsRequiredError) Unwrap() error { return e.APIError }
