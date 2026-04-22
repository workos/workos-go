// @oagen-ignore-file

package workos_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6"
)

const testCookiePassword = "test-cookie-password-for-session-helpers"

// buildFakeJWT builds a fake JWT: header.payload.signature
func buildFakeJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sid":"sess_123","org_id":"org_456","role":"admin","permissions":["read","write"]}`))
	return header + "." + payload + ".fakesig"
}

func TestSealSessionFromAuthResponse_SealAndUnseal(t *testing.T) {
	fakeJWT := buildFakeJWT()

	user := &workos.User{
		ID:    "user_123",
		Email: "test@example.com",
	}

	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		user,
		nil, // no impersonator
		testCookiePassword,
	)
	require.NoError(t, err)
	require.NotEmpty(t, sealed)

	// Verify the sealed data can be unsealed
	unsealed, err := workos.UnsealData(sealed, testCookiePassword)
	require.NoError(t, err)
	require.Equal(t, fakeJWT, unsealed["access_token"])
	require.Equal(t, "refresh_tok_abc", unsealed["refresh_token"])

	userMap, ok := unsealed["user"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "user_123", userMap["id"])
	require.Equal(t, "test@example.com", userMap["email"])
}

func TestSealSessionFromAuthResponse_WithImpersonator(t *testing.T) {
	fakeJWT := buildFakeJWT()

	user := &workos.User{ID: "user_123"}
	impersonator := &workos.AuthenticateResponseImpersonator{
		Email:  "admin@example.com",
		Reason: ptrString("debugging"),
	}

	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		user,
		impersonator,
		testCookiePassword,
	)
	require.NoError(t, err)
	require.NotEmpty(t, sealed)

	unsealed, err := workos.UnsealData(sealed, testCookiePassword)
	require.NoError(t, err)

	impMap, ok := unsealed["impersonator"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "admin@example.com", impMap["email"])
}

func TestAuthenticateSession_ValidSession(t *testing.T) {
	fakeJWT := buildFakeJWT()

	// Seal a session containing the fake JWT as the access_token
	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		&workos.User{ID: "user_123", Email: "test@example.com"},
		nil,
		testCookiePassword,
	)
	require.NoError(t, err)

	result, err := workos.AuthenticateSession(sealed, testCookiePassword)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Authenticated)
	require.Equal(t, "sess_123", result.SessionID)
	require.Equal(t, "org_456", result.OrganizationID)
	require.Equal(t, "admin", result.Role)
	require.Equal(t, []string{"read", "write"}, result.Permissions)

	// User data should be populated
	require.NotNil(t, result.User)
	require.Equal(t, "user_123", result.User.ID)
}

func TestAuthenticateSession_EmptySession(t *testing.T) {
	result, err := workos.AuthenticateSession("", testCookiePassword)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.Authenticated)
	require.Equal(t, "no_session_cookie_provided", result.Reason)
}

func TestAuthenticateSession_InvalidSealedData(t *testing.T) {
	result, err := workos.AuthenticateSession("not-valid-sealed-data", testCookiePassword)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.Authenticated)
	require.Equal(t, "invalid_session_cookie", result.Reason)
}

func TestAuthenticateSession_WrongPassword(t *testing.T) {
	fakeJWT := buildFakeJWT()

	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		nil,
		nil,
		testCookiePassword,
	)
	require.NoError(t, err)

	// Try to unseal with the wrong password
	result, err := workos.AuthenticateSession(sealed, "wrong-password")
	require.NoError(t, err)
	require.False(t, result.Authenticated)
	require.Equal(t, "invalid_session_cookie", result.Reason)
}

func TestNewSession_Authenticate(t *testing.T) {
	fakeJWT := buildFakeJWT()

	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		&workos.User{ID: "user_789"},
		nil,
		testCookiePassword,
	)
	require.NoError(t, err)

	// Create a Session object and authenticate
	session := workos.NewSession(nil, sealed, testCookiePassword)
	require.NotNil(t, session)

	result, err := session.Authenticate()
	require.NoError(t, err)
	require.True(t, result.Authenticated)
	require.Equal(t, "sess_123", result.SessionID)
	require.Equal(t, "org_456", result.OrganizationID)
	require.Equal(t, "admin", result.Role)
	require.Equal(t, []string{"read", "write"}, result.Permissions)
	require.NotNil(t, result.User)
	require.Equal(t, "user_789", result.User.ID)
}

func TestNewSession_Authenticate_EmptySession(t *testing.T) {
	session := workos.NewSession(nil, "", testCookiePassword)
	result, err := session.Authenticate()
	require.NoError(t, err)
	require.False(t, result.Authenticated)
	require.Equal(t, "no_session_cookie_provided", result.Reason)
}

func TestAuthenticateSession_NoAccessToken(t *testing.T) {
	// Seal data that has no access_token field
	data := map[string]interface{}{
		"refresh_token": "refresh_tok_abc",
	}
	sealed, err := workos.SealData(data, testCookiePassword)
	require.NoError(t, err)

	result, err := workos.AuthenticateSession(sealed, testCookiePassword)
	require.NoError(t, err)
	require.False(t, result.Authenticated)
	require.Equal(t, "invalid_jwt", result.Reason)
}
