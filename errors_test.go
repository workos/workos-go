// @oagen-ignore-file

package workos

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// helper that creates a client pointed at a test server returning the given status and body.
func errTestClient(status int, body string) (*Client, func()) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_test_123")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	client := NewClient("sk_test", WithBaseURL(server.URL))
	return client, server.Close
}

func TestAPIError_OAuthFields(t *testing.T) {
	client, close := errTestClient(400, `{
		"error": "invalid_client",
		"error_description": "Invalid client_id."
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	require.Equal(t, 400, apiErr.StatusCode)
	require.Equal(t, "invalid_client", apiErr.ErrorCode)
	require.Equal(t, "Invalid client_id.", apiErr.ErrorDescription)
	require.Equal(t, "req_test_123", apiErr.RequestID)
}

func TestAPIError_CodeMessageFormat(t *testing.T) {
	client, close := errTestClient(400, `{
		"code": "invalid_audit_logs",
		"message": "Invalid Audit",
		"errors": ["another_error"]
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	require.Equal(t, "invalid_audit_logs", apiErr.Code)
	require.Equal(t, "Invalid Audit", apiErr.Message)
	require.Equal(t, []string{"another_error"}, apiErr.Errors)
}

func TestEmailVerificationRequiredError(t *testing.T) {
	client, close := errTestClient(422, `{
		"code": "email_verification_required",
		"message": "Email ownership must be verified before authentication.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"email": "marcelina.davis@example.com",
		"email_verification_id": "email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3"
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var emailErr *EmailVerificationRequiredError
	require.True(t, errors.As(err, &emailErr))
	require.Equal(t, "email_verification_required", emailErr.Code)
	require.Equal(t, "marcelina.davis@example.com", emailErr.Email)
	require.Equal(t, "email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3", emailErr.EmailVerificationID)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", emailErr.PendingAuthenticationToken)
	require.Equal(t, "req_test_123", emailErr.RequestID)
}

func TestMFAEnrollmentError(t *testing.T) {
	client, close := errTestClient(422, `{
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
			"created_at": "2021-06-25T19:07:33.155Z",
			"updated_at": "2021-06-25T19:07:33.155Z"
		}
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var mfaErr *MFAEnrollmentError
	require.True(t, errors.As(err, &mfaErr))
	require.Equal(t, "mfa_enrollment", mfaErr.Code)
	require.Equal(t, "user_01E4ZCR3C56J083X43JQXF3JK5", mfaErr.User.ID)
	require.Equal(t, "marcelina.davis@example.com", mfaErr.User.Email)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", mfaErr.PendingAuthenticationToken)
}

func TestMFAEnrollmentError_NilUserFallsBack(t *testing.T) {
	client, close := errTestClient(422, `{
		"code": "mfa_enrollment",
		"message": "User needs to enroll in MFA.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S"
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	// Should fall back to UnprocessableEntityError, not MFAEnrollmentError.
	var mfaErr *MFAEnrollmentError
	require.False(t, errors.As(err, &mfaErr))

	var unprocessableErr *UnprocessableEntityError
	require.True(t, errors.As(err, &unprocessableErr))
	require.Equal(t, "mfa_enrollment", unprocessableErr.Code)
}

func TestMFAChallengeError(t *testing.T) {
	client, close := errTestClient(422, `{
		"code": "mfa_challenge",
		"message": "The user must complete an MFA challenge to finish authenticating.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"authentication_factors": [
			{"id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ", "type": "totp"}
		],
		"user": {
			"object": "user",
			"id": "user_01E4ZCR3C56J083X43JQXF3JK5",
			"email": "marcelina.davis@example.com",
			"first_name": "Marcelina",
			"last_name": "Davis",
			"email_verified": true,
			"created_at": "2021-06-25T19:07:33.155Z",
			"updated_at": "2021-06-25T19:07:33.155Z"
		}
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var mfaErr *MFAChallengeError
	require.True(t, errors.As(err, &mfaErr))
	require.Equal(t, "mfa_challenge", mfaErr.Code)
	require.Equal(t, "user_01E4ZCR3C56J083X43JQXF3JK5", mfaErr.User.ID)
	require.Len(t, mfaErr.AuthenticationFactors, 1)
	require.Equal(t, "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ", mfaErr.AuthenticationFactors[0].ID)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", mfaErr.PendingAuthenticationToken)
}

func TestOrganizationSelectionRequiredError(t *testing.T) {
	client, close := errTestClient(422, `{
		"code": "organization_selection_required",
		"message": "The user must choose an organization to finish their authentication.",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S",
		"organizations": [
			{"id": "org_01H93RZAP85YGYZJXYPAZ9QTXF", "name": "Foo Corp"},
			{"id": "org_01H93S4E6GB5A8PFNKGTA4S42X", "name": "Bar Corp"}
		],
		"user": {
			"object": "user",
			"id": "user_01E4ZCR3C56J083X43JQXF3JK5",
			"email": "marcelina.davis@example.com",
			"first_name": "Marcelina",
			"last_name": "Davis",
			"email_verified": true,
			"created_at": "2021-06-25T19:07:33.155Z",
			"updated_at": "2021-06-25T19:07:33.155Z"
		}
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var orgErr *OrganizationSelectionRequiredError
	require.True(t, errors.As(err, &orgErr))
	require.Equal(t, "organization_selection_required", orgErr.Code)
	require.Equal(t, "user_01E4ZCR3C56J083X43JQXF3JK5", orgErr.User.ID)
	require.Len(t, orgErr.Organizations, 2)
	require.Equal(t, "org_01H93RZAP85YGYZJXYPAZ9QTXF", orgErr.Organizations[0].ID)
	require.Equal(t, "Foo Corp", orgErr.Organizations[0].Name)
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", orgErr.PendingAuthenticationToken)
}

func TestSSORequiredError(t *testing.T) {
	client, close := errTestClient(422, `{
		"error": "sso_required",
		"error_description": "User must authenticate using one of the matching connections.",
		"connection_ids": ["conn_01DRF1T7JN6GXS8KHS0WYWX1YD"],
		"email": "marcelina.davis@example.com",
		"pending_authentication_token": "YQyCkYfuVw2mI3tzSrk2C1Y7S"
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var ssoErr *SSORequiredError
	require.True(t, errors.As(err, &ssoErr))
	require.Equal(t, "sso_required", ssoErr.ErrorCode)
	require.Equal(t, "marcelina.davis@example.com", ssoErr.Email)
	require.Len(t, ssoErr.ConnectionIDs, 1)
	require.Equal(t, "conn_01DRF1T7JN6GXS8KHS0WYWX1YD", ssoErr.ConnectionIDs[0])
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", ssoErr.PendingAuthenticationToken)
}

func TestOrganizationAuthenticationMethodsRequiredError(t *testing.T) {
	client, close := errTestClient(422, `{
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
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var orgAuthErr *OrganizationAuthenticationMethodsRequiredError
	require.True(t, errors.As(err, &orgAuthErr))
	require.Equal(t, "organization_authentication_methods_required", orgAuthErr.ErrorCode)
	require.Equal(t, "marcelina.davis@example.com", orgAuthErr.Email)
	require.Len(t, orgAuthErr.SSOConnectionIDs, 1)
	require.True(t, orgAuthErr.AuthMethods["google_oauth"])
	require.False(t, orgAuthErr.AuthMethods["password"])
	require.Equal(t, "YQyCkYfuVw2mI3tzSrk2C1Y7S", orgAuthErr.PendingAuthenticationToken)
}

func TestNonAuthErrorFallsBackToGeneric(t *testing.T) {
	client, close := errTestClient(400, `{
		"code": "invalid_request",
		"message": "Invalid request"
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	// Should not match any authentication error type.
	var emailErr *EmailVerificationRequiredError
	var mfaErr *MFAEnrollmentError
	var ssoErr *SSORequiredError
	require.False(t, errors.As(err, &emailErr))
	require.False(t, errors.As(err, &mfaErr))
	require.False(t, errors.As(err, &ssoErr))

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	require.Equal(t, "invalid_request", apiErr.Code)
	require.Equal(t, "Invalid request", apiErr.Message)
}

func TestAPIError_UnwrapChain(t *testing.T) {
	client, close := errTestClient(401, `{
		"code": "unauthorized",
		"message": "Bad API key"
	}`)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	// Should be an AuthenticationError that unwraps to APIError.
	var authErr *AuthenticationError
	require.True(t, errors.As(err, &authErr))

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	require.Equal(t, 401, apiErr.StatusCode)
}

func TestAPIError_RawBodyPreserved(t *testing.T) {
	body := `{"error":"invalid_grant","error_description":"The code has expired."}`
	client, close := errTestClient(400, body)
	defer close()

	_, err := client.Organizations().Get(context.Background(), "org_123")
	require.Error(t, err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	require.Equal(t, body, apiErr.RawBody)
}
