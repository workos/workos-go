package workos_errors

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmailVerificationRequiredError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"code": "email_verification_required",
		"message": "Email ownership must be verified before authentication.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"email": "marcelina.davis@example.com",
		"email_verification_id": "email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3"
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Test type assertion using standard errors.As
	var emailErr *EmailVerificationRequiredError
	require.True(t, errors.As(err, &emailErr))
	require.NotNil(t, emailErr)
	require.Equal(t, "email_verification_required", emailErr.ErrorCode)
	require.Equal(t, "email_verification_required", emailErr.Code)
	require.Equal(t, "Email ownership must be verified before authentication.", emailErr.Message)
	require.Equal(t, "marcelina.davis@example.com", emailErr.Email)
	require.Equal(t, "email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3", emailErr.EmailVerificationID)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", emailErr.PendingAuthenticationToken)
	require.Equal(t, "test-request-id", emailErr.RequestID)
}

func TestMFAEnrollmentError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"code": "mfa_enrollment",
		"message": "The user must enroll in MFA to finish authenticating.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"user": {
			"object": "user",
			"id": "user_01E4ZCR3C56J083X43JQXF3JK5",
			"email": "marcelina.davis@example.com",
			"first_name": "Marcelina",
			"last_name": "Davis",
			"email_verified": true,
			"profile_picture_url": "https://workoscdn.com/images/v1/123abc",
			"created_at": "2021-06-25T19:07:33.155Z",
			"updated_at": "2021-06-25T19:07:33.155Z"
		}
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Test type assertion using standard errors.As
	var mfaErr *MFAEnrollmentError
	require.True(t, errors.As(err, &mfaErr))
	require.NotNil(t, mfaErr)
	require.Equal(t, "mfa_enrollment", mfaErr.ErrorCode)
	require.Equal(t, "user_01E4ZCR3C56J083X43JQXF3JK5", mfaErr.User.ID)
	require.Equal(t, "marcelina.davis@example.com", mfaErr.User.Email)
	require.Equal(t, "Marcelina", mfaErr.User.FirstName)
	require.Equal(t, "Davis", mfaErr.User.LastName)
	require.True(t, mfaErr.User.EmailVerified)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", mfaErr.PendingAuthenticationToken)
}

func TestMFAChallengeError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"code": "mfa_challenge",
		"message": "The user must complete an MFA challenge to finish authenticating.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"authentication_factors": [
			{
				"id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
				"type": "totp"
			}
		],
		"user": {
			"object": "user",
			"id": "user_01E4ZCR3C56J083X43JQXF3JK5",
			"email": "marcelina.davis@example.com",
			"first_name": "Marcelina",
			"last_name": "Davis",
			"email_verified": true,
			"profile_picture_url": "https://workoscdn.com/images/v1/123abc",
			"created_at": "2021-06-25T19:07:33.155Z",
			"updated_at": "2021-06-25T19:07:33.155Z"
		}
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Test type assertion using standard errors.As
	var mfaErr *MFAChallengeError
	require.True(t, errors.As(err, &mfaErr))
	require.NotNil(t, mfaErr)
	require.Equal(t, "mfa_challenge", mfaErr.ErrorCode)
	require.Equal(t, "user_01E4ZCR3C56J083X43JQXF3JK5", mfaErr.User.ID)
	require.Equal(t, "marcelina.davis@example.com", mfaErr.User.Email)
	require.Len(t, mfaErr.AuthenticationFactors, 1)
	require.Equal(t, "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ", mfaErr.AuthenticationFactors[0].ID)
	require.Equal(t, TOTP, mfaErr.AuthenticationFactors[0].Type)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", mfaErr.PendingAuthenticationToken)
}

func TestOrganizationSelectionRequiredError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"code": "organization_selection_required",
		"message": "The user must choose an organization to finish their authentication.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"organizations": [
			{
				"id": "org_01H93RZAP85YGYZJXYPAZ9QTXF",
				"name": "Foo Corp"
			},
			{
				"id": "org_01H93S4E6GB5A8PFNKGTA4S42X",
				"name": "Bar Corp"
			}
		],
		"user": {
			"object": "user",
			"id": "user_01E4ZCR3C56J083X43JQXF3JK5",
			"email": "marcelina.davis@example.com",
			"first_name": "Marcelina",
			"last_name": "Davis",
			"email_verified": true,
			"profile_picture_url": "https://workoscdn.com/images/v1/123abc",
			"created_at": "2021-06-25T19:07:33.155Z",
			"updated_at": "2021-06-25T19:07:33.155Z"
		}
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Test type assertion using standard errors.As
	var orgErr *OrganizationSelectionRequiredError
	require.True(t, errors.As(err, &orgErr))
	require.NotNil(t, orgErr)
	require.Equal(t, "organization_selection_required", orgErr.ErrorCode)
	require.Equal(t, "user_01E4ZCR3C56J083X43JQXF3JK5", orgErr.User.ID)
	require.Equal(t, "marcelina.davis@example.com", orgErr.User.Email)
	require.Len(t, orgErr.Organizations, 2)
	require.Equal(t, "org_01H93RZAP85YGYZJXYPAZ9QTXF", orgErr.Organizations[0].ID)
	require.Equal(t, "Foo Corp", orgErr.Organizations[0].Name)
	require.Equal(t, "org_01H93S4E6GB5A8PFNKGTA4S42X", orgErr.Organizations[1].ID)
	require.Equal(t, "Bar Corp", orgErr.Organizations[1].Name)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", orgErr.PendingAuthenticationToken)
}

func TestSSORequiredError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"error": "sso_required",
		"error_description": "User must authenticate using one of the matching connections.",
		"connection_ids": ["conn_01DRF1T7JN6GXS8KHS0WYWX1YD"],
		"email": "marcelina.davis@example.com",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S"
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Test type assertion using standard errors.As
	var ssoErr *SSORequiredError
	require.True(t, errors.As(err, &ssoErr))
	require.NotNil(t, ssoErr)
	require.Equal(t, "sso_required", ssoErr.ErrorCode)
	require.Equal(t, "marcelina.davis@example.com", ssoErr.Email)
	require.Len(t, ssoErr.ConnectionIDs, 1)
	require.Equal(t, "conn_01DRF1T7JN6GXS8KHS0WYWX1YD", ssoErr.ConnectionIDs[0])
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", ssoErr.PendingAuthenticationToken)
}

func TestOrganizationAuthenticationMethodsRequiredError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"error": "organization_authentication_methods_required",
		"error_description": "User must authenticate using one of the methods allowed by the organization.",
		"sso_connection_ids": ["conn_01DRF1T7JN6GXS8KHS0WYWX1YD"],
		"auth_methods": {
			"apple_oauth": false,
			"github_oauth": false,
			"google_oauth": true,
			"magic_auth": false,
			"microsoft_oauth": false,
			"password": false
		},
		"email": "marcelina.davis@example.com",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S"
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Test type assertion using standard errors.As
	var orgAuthErr *OrganizationAuthenticationMethodsRequiredError
	require.True(t, errors.As(err, &orgAuthErr))
	require.NotNil(t, orgAuthErr)
	require.Equal(t, "organization_authentication_methods_required", orgAuthErr.ErrorCode)
	require.Equal(t, "marcelina.davis@example.com", orgAuthErr.Email)
	require.Len(t, orgAuthErr.SSOConnectionIDs, 1)
	require.Equal(t, "conn_01DRF1T7JN6GXS8KHS0WYWX1YD", orgAuthErr.SSOConnectionIDs[0])
	require.Len(t, orgAuthErr.AuthMethods, 6)
	require.False(t, orgAuthErr.AuthMethods["apple_oauth"])
	require.False(t, orgAuthErr.AuthMethods["github_oauth"])
	require.True(t, orgAuthErr.AuthMethods["google_oauth"])
	require.False(t, orgAuthErr.AuthMethods["magic_auth"])
	require.False(t, orgAuthErr.AuthMethods["microsoft_oauth"])
	require.False(t, orgAuthErr.AuthMethods["password"])
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", orgAuthErr.PendingAuthenticationToken)
}

func TestNonAuthenticationErrorFallsBackToGeneric(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusBadRequest)
	rec.WriteString(`{
		"message": "Invalid request",
		"code": "invalid_request"
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Should not be any of the authentication error types
	var emailErr *EmailVerificationRequiredError
	var mfaErr *MFAEnrollmentError
	var mfaChallengeErr *MFAChallengeError
	var orgErr *OrganizationSelectionRequiredError
	var ssoErr *SSORequiredError
	var orgAuthErr *OrganizationAuthenticationMethodsRequiredError

	require.False(t, errors.As(err, &emailErr))
	require.False(t, errors.As(err, &mfaErr))
	require.False(t, errors.As(err, &mfaChallengeErr))
	require.False(t, errors.As(err, &orgErr))
	require.False(t, errors.As(err, &ssoErr))
	require.False(t, errors.As(err, &orgAuthErr))

	// Should be a generic HTTPError
	httpErr, ok := err.(HTTPError)
	require.True(t, ok)
	require.Equal(t, http.StatusBadRequest, httpErr.Code)
	require.Equal(t, "Invalid request", httpErr.Message)
	require.Equal(t, "invalid_request", httpErr.ErrorCode)
}

func TestTypeAssertionFunctionsReturnFalseForWrongTypes(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusBadRequest)
	rec.WriteString(`{
		"message": "Invalid request",
		"code": "invalid_request"
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// All type assertions should return false for non-authentication errors
	var emailErr *EmailVerificationRequiredError
	var mfaErr *MFAEnrollmentError
	var mfaChallengeErr *MFAChallengeError
	var orgErr *OrganizationSelectionRequiredError
	var ssoErr *SSORequiredError
	var orgAuthErr *OrganizationAuthenticationMethodsRequiredError

	require.False(t, errors.As(err, &emailErr))
	require.False(t, errors.As(err, &mfaErr))
	require.False(t, errors.As(err, &mfaChallengeErr))
	require.False(t, errors.As(err, &orgErr))
	require.False(t, errors.As(err, &ssoErr))
	require.False(t, errors.As(err, &orgAuthErr))
}

func TestErrorStringFormatting(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"code": "email_verification_required",
		"message": "Email ownership must be verified before authentication.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"email": "marcelina.davis@example.com",
		"email_verification_id": "email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3"
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Test that the error message includes the expected information
	errMsg := err.Error()
	require.Contains(t, errMsg, "422 Unprocessable Entity")
	require.Contains(t, errMsg, "test-request-id")
	require.Contains(t, errMsg, "Email ownership must be verified before authentication")
	require.Contains(t, errMsg, "pending_authentication_token: \"YQyCkYfuVw2mI3tzSrk2C1Y7S\"")
	require.Contains(t, errMsg, "email_verification_id: \"email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3\"")
}

func TestFactorTypeEnum(t *testing.T) {
	// Test that FactorType constants are correctly defined
	require.Equal(t, "sms", string(SMS))
	require.Equal(t, "totp", string(TOTP))

	// Test JSON marshaling/unmarshaling
	factor := AuthenticationFactor{
		ID:   "test_id",
		Type: TOTP,
	}

	data, err := json.Marshal(factor)
	require.NoError(t, err)

	var unmarshaledFactor AuthenticationFactor
	err = json.Unmarshal(data, &unmarshaledFactor)
	require.NoError(t, err)

	require.Equal(t, factor.ID, unmarshaledFactor.ID)
	require.Equal(t, factor.Type, unmarshaledFactor.Type)
	require.Equal(t, TOTP, unmarshaledFactor.Type)
}

func TestAuthenticationErrorWithNilUserFallsBackToGeneric(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "test-request-id")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{
		"code": "mfa_enrollment",
		"message": "User needs to enroll in MFA.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S"
	}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	// Should fall back to generic HTTPError, not structured MFAEnrollmentError
	var mfaErr *MFAEnrollmentError
	require.False(t, errors.As(err, &mfaErr))

	// Should be a generic HTTPError
	var httpErr HTTPError
	require.True(t, errors.As(err, &httpErr))
	require.Equal(t, "mfa_enrollment", httpErr.ErrorCode)
	require.Equal(t, "User needs to enroll in MFA.", httpErr.Message)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", httpErr.PendingAuthenticationToken)
}
