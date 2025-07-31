package workos_errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/workos/workos-go/v4/pkg/common"
)

// TryGetHTTPError returns an error when the http response contains invalid
// status code.
func TryGetHTTPError(r *http.Response) error {
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		return nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return HTTPError{
			Code:    r.StatusCode,
			Status:  r.Status,
			Message: err.Error(),
		}
	}

	// Try to parse as authentication error first
	if isJsonResponse(r) {
		if authErr := parseAuthenticationError(body, r.StatusCode); authErr != nil {
			// Set RequestID on the error
			requestID := r.Header.Get("X-Request-ID")
			if httpErr, ok := authErr.(*HTTPError); ok {
				httpErr.RequestID = requestID
			} else if httpErr, ok := authErr.(HTTPError); ok {
				httpErr.RequestID = requestID
				return httpErr
			} else {
				// For structured authentication errors, set the RequestID on the embedded HTTPError
				switch e := authErr.(type) {
				case *EmailVerificationRequiredError:
					e.RequestID = requestID
				case *MFAEnrollmentError:
					e.RequestID = requestID
				case *MFAChallengeError:
					e.RequestID = requestID
				case *OrganizationSelectionRequiredError:
					e.RequestID = requestID
				case *SSORequiredError:
					e.RequestID = requestID
				case *OrganizationAuthenticationMethodsRequiredError:
					e.RequestID = requestID
				}
			}
			return authErr
		}
	}

	// Fall back to generic error parsing
	var msg, code string
	var errors []string
	var fieldErrors []FieldError
	var pendingAuthToken, emailVerificationID string

	if isJsonResponse(r) {
		msg, code, errors, fieldErrors, pendingAuthToken, emailVerificationID = getJsonErrorMessage(body, r.StatusCode)
	} else {
		msg = string(body)
	}

	return HTTPError{
		Code:                       r.StatusCode,
		Status:                     r.Status,
		RequestID:                  r.Header.Get("X-Request-ID"),
		Message:                    msg,
		ErrorCode:                  code,
		Errors:                     errors,
		FieldErrors:                fieldErrors,
		RawBody:                    string(body),
		PendingAuthenticationToken: pendingAuthToken,
		EmailVerificationID:        emailVerificationID,
	}
}

func isJsonResponse(r *http.Response) bool {

	return strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

// ErrorWithMessage struct to hold a single error with a message
type ErrorWithMessage struct {
	Message string `json:"message"`
}

// ResponseErrors is a custom type that can handle unmarshaling []string or []ErrorWithMessage
type ResponseErrors []string

func (e *ResponseErrors) UnmarshalJSON(data []byte) error {
	// Try unmarshaling as []string
	var stringErrors []string
	if err := json.Unmarshal(data, &stringErrors); err == nil {
		*e = stringErrors
		return nil
	}

	// Try unmarshaling as []ErrorWithMessage
	var structErrors []ErrorWithMessage
	if err := json.Unmarshal(data, &structErrors); err == nil {
		for _, se := range structErrors {
			*e = append(*e, se.Message)
		}
		return nil
	}

	return errors.New("errors field is not a valid format")
}

func getJsonErrorMessage(b []byte, statusCode int) (string, string, []string, []FieldError, string, string) {
	if statusCode == 422 {
		var unprocesableEntityPayload struct {
			Message                    string       `json:"message"`
			Error                      string       `json:"error"`
			ErrorDescription           string       `json:"error_description"`
			FieldErrors                []FieldError `json:"errors"`
			Code                       string       `json:"code"`
			PendingAuthenticationToken string       `json:"pending_authentication_token"`
			EmailVerificationID        string       `json:"email_verification_id"`
		}

		if err := json.Unmarshal(b, &unprocesableEntityPayload); err != nil {
			return string(b), "", nil, nil, "", ""
		}

		return unprocesableEntityPayload.Message,
			unprocesableEntityPayload.Code,
			nil,
			unprocesableEntityPayload.FieldErrors,
			unprocesableEntityPayload.PendingAuthenticationToken,
			unprocesableEntityPayload.EmailVerificationID
	}

	var payload struct {
		Message                    string         `json:"message"`
		Error                      string         `json:"error"`
		ErrorDescription           string         `json:"error_description"`
		Errors                     ResponseErrors `json:"errors"`
		Code                       string         `json:"code"`
		PendingAuthenticationToken string         `json:"pending_authentication_token"`
		EmailVerificationID        string         `json:"email_verification_id"`
	}

	if err := json.Unmarshal(b, &payload); err != nil {
		return string(b), "", nil, nil, "", ""
	}

	if payload.Error != "" && payload.ErrorDescription != "" {
		return fmt.Sprintf("%s %s", payload.Error, payload.ErrorDescription), payload.Error, nil, nil, payload.PendingAuthenticationToken, payload.EmailVerificationID
	} else if payload.Message != "" && len(payload.Errors) == 0 {
		return payload.Message, payload.Code, nil, nil, payload.PendingAuthenticationToken, payload.EmailVerificationID
	} else if payload.Message != "" && len(payload.Errors) > 0 {
		return payload.Message, payload.Code, payload.Errors, nil, payload.PendingAuthenticationToken, payload.EmailVerificationID
	}

	return string(b), "", nil, nil, "", ""
}

// parseAuthenticationError creates the appropriate structured error type based on the error code
func parseAuthenticationError(b []byte, statusCode int) error {
	// Try parsing with code/message format first
	var payload struct {
		Message                    string                                  `json:"message"`
		Code                       string                                  `json:"code"`
		PendingAuthenticationToken string                                  `json:"pending_authentication_token"`
		EmailVerificationID        string                                  `json:"email_verification_id"`
		Email                      string                                  `json:"email"`
		User                       *common.User                            `json:"user"`
		AuthenticationFactors      []AuthenticationFactor                  `json:"authentication_factors"`
		Organizations              []PendingAuthenticationOrganizationInfo `json:"organizations"`
		ConnectionIDs              []string                                `json:"connection_ids"`
		SSOConnectionIDs           []string                                `json:"sso_connection_ids"`
		AuthMethods                map[string]bool                         `json:"auth_methods"`
	}

	if err := json.Unmarshal(b, &payload); err == nil && payload.Code != "" {
		// Create base HTTPError
		httpErr := HTTPError{
			Code:                       statusCode,
			Status:                     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
			Message:                    payload.Message,
			ErrorCode:                  payload.Code,
			PendingAuthenticationToken: payload.PendingAuthenticationToken,
			EmailVerificationID:        payload.EmailVerificationID,
			AuthenticationFactors:      payload.AuthenticationFactors,
			Organizations:              payload.Organizations,
			ConnectionIDs:              payload.ConnectionIDs,
			SSOConnectionIDs:           payload.SSOConnectionIDs,
			AuthMethods:                payload.AuthMethods,
			User:                       payload.User,
			RawBody:                    string(b),
		}

		// Return appropriate structured error based on code
		switch payload.Code {
		case EmailVerificationRequiredCode:
			return &EmailVerificationRequiredError{
				HTTPError:                  httpErr,
				Code:                       payload.Code,
				Message:                    payload.Message,
				Email:                      payload.Email,
				EmailVerificationID:        payload.EmailVerificationID,
				PendingAuthenticationToken: payload.PendingAuthenticationToken,
			}
		case MFAEnrollmentCode:
			if payload.User != nil {
				return &MFAEnrollmentError{
					HTTPError:                  httpErr,
					Code:                       payload.Code,
					Message:                    payload.Message,
					User:                       *payload.User,
					PendingAuthenticationToken: payload.PendingAuthenticationToken,
				}
			} else {
				// If User is nil, fall back to generic error parsing
				return nil
			}
		case MFAChallengeCode:
			if payload.User != nil {
				return &MFAChallengeError{
					HTTPError:                  httpErr,
					Code:                       payload.Code,
					Message:                    payload.Message,
					User:                       *payload.User,
					AuthenticationFactors:      payload.AuthenticationFactors,
					PendingAuthenticationToken: payload.PendingAuthenticationToken,
				}
			} else {
				// If User is nil, fall back to generic error parsing
				return nil
			}
		case OrganizationSelectionRequiredCode:
			if payload.User != nil {
				return &OrganizationSelectionRequiredError{
					HTTPError:                  httpErr,
					Code:                       payload.Code,
					Message:                    payload.Message,
					User:                       *payload.User,
					Organizations:              payload.Organizations,
					PendingAuthenticationToken: payload.PendingAuthenticationToken,
				}
			} else {
				// If User is nil, fall back to generic error parsing
				return nil
			}
		}
	}

	// Try parsing with error/error_description format for SSO and org auth methods
	var errorPayload struct {
		Error                      string          `json:"error"`
		ErrorDescription           string          `json:"error_description"`
		PendingAuthenticationToken string          `json:"pending_authentication_token"`
		Email                      string          `json:"email"`
		ConnectionIDs              []string        `json:"connection_ids"`
		SSOConnectionIDs           []string        `json:"sso_connection_ids"`
		AuthMethods                map[string]bool `json:"auth_methods"`
	}

	if err := json.Unmarshal(b, &errorPayload); err == nil && errorPayload.Error != "" {
		// Create base HTTPError
		httpErr := HTTPError{
			Code:                       statusCode,
			Status:                     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
			Message:                    fmt.Sprintf("%s %s", errorPayload.Error, errorPayload.ErrorDescription),
			ErrorCode:                  errorPayload.Error,
			PendingAuthenticationToken: errorPayload.PendingAuthenticationToken,
			ConnectionIDs:              errorPayload.ConnectionIDs,
			SSOConnectionIDs:           errorPayload.SSOConnectionIDs,
			AuthMethods:                errorPayload.AuthMethods,
			RawBody:                    string(b),
		}

		// Return appropriate structured error based on error type
		switch errorPayload.Error {
		case SSORequiredCode:
			return &SSORequiredError{
				HTTPError:                  httpErr,
				ErrorCode:                  errorPayload.Error,
				ErrorDescription:           errorPayload.ErrorDescription,
				Email:                      errorPayload.Email,
				ConnectionIDs:              errorPayload.ConnectionIDs,
				PendingAuthenticationToken: errorPayload.PendingAuthenticationToken,
			}
		case OrganizationAuthenticationMethodsRequiredCode:
			return &OrganizationAuthenticationMethodsRequiredError{
				HTTPError:                  httpErr,
				ErrorCode:                  errorPayload.Error,
				ErrorDescription:           errorPayload.ErrorDescription,
				Email:                      errorPayload.Email,
				SSOConnectionIDs:           errorPayload.SSOConnectionIDs,
				AuthMethods:                errorPayload.AuthMethods,
				PendingAuthenticationToken: errorPayload.PendingAuthenticationToken,
			}
		}
	}

	// If no specific error type matches, return nil to fall back to generic parsing
	return nil
}

// HTTPError represents an http error.
type HTTPError struct {
	Code                       int
	Status                     string
	RequestID                  string
	Message                    string
	ErrorCode                  string
	Errors                     []string
	FieldErrors                []FieldError
	ErrorDescription           string
	RawBody                    string
	PendingAuthenticationToken string
	EmailVerificationID        string
	// Authentication error specific fields
	AuthenticationFactors []AuthenticationFactor                  `json:"authentication_factors,omitempty"`
	Organizations         []PendingAuthenticationOrganizationInfo `json:"organizations,omitempty"`
	ConnectionIDs         []string                                `json:"connection_ids,omitempty"`
	SSOConnectionIDs      []string                                `json:"sso_connection_ids,omitempty"`
	AuthMethods           map[string]bool                         `json:"auth_methods,omitempty"`
	User                  *common.User                            `json:"user,omitempty"`
}

type FieldError struct {
	Field string
	Code  string
}

func (e HTTPError) Error() string {
	baseMsg := fmt.Sprintf("%s: request id %q: %s", e.Status, e.RequestID, e.Message)

	// Add additional fields if they exist
	if e.PendingAuthenticationToken != "" {
		baseMsg += fmt.Sprintf(", pending_authentication_token: %q", e.PendingAuthenticationToken)
	}

	if e.EmailVerificationID != "" {
		baseMsg += fmt.Sprintf(", email_verification_id: %q", e.EmailVerificationID)
	}

	return baseMsg
}
