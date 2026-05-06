// @oagen-ignore-file

package workos_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v8"
)

func TestGetSSOAuthorizationURL_BuildsCorrectURL(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	provider := "GoogleOAuth"
	state := "custom_state"
	result, err := client.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
		Provider:    &provider,
		State:       &state,
	})
	require.NoError(t, err)

	parsed, err := url.Parse(result)
	require.NoError(t, err)

	require.Equal(t, "https", parsed.Scheme)
	require.Equal(t, "api.workos.com", parsed.Host)
	require.Equal(t, "/sso/authorize", parsed.Path)

	q := parsed.Query()
	require.Equal(t, "client_123", q.Get("client_id"))
	require.Equal(t, "https://example.com/callback", q.Get("redirect_uri"))
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "GoogleOAuth", q.Get("provider"))
	require.Equal(t, "custom_state", q.Get("state"))
}

func TestGetSSOAuthorizationURL_FailsWithoutRedirectURI(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
	)

	_, err := client.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "redirect_uri is required")
}

func TestGetSSOAuthorizationURL_FailsWithoutClientID(t *testing.T) {
	client := workos.NewClient("sk_test")

	_, err := client.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_id is required")
}

func TestGetSSOAuthorizationURL_AllOptionalParams(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	provider := "GoogleOAuth"
	connectionID := "conn_abc"
	organizationID := "org_def"
	domainHint := "example.com"
	loginHint := "user@example.com"
	state := "my_state"
	codeChallenge := "challenge_value"
	codeChallengeMethod := "S256"

	result, err := client.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{
		RedirectURI:         "https://example.com/callback",
		Provider:            &provider,
		ConnectionID:        &connectionID,
		OrganizationID:      &organizationID,
		DomainHint:          &domainHint,
		LoginHint:           &loginHint,
		State:               &state,
		CodeChallenge:       &codeChallenge,
		CodeChallengeMethod: &codeChallengeMethod,
	})
	require.NoError(t, err)

	parsed, err := url.Parse(result)
	require.NoError(t, err)

	q := parsed.Query()
	require.Equal(t, "conn_abc", q.Get("connection_id"))
	require.Equal(t, "org_def", q.Get("organization_id"))
	require.Equal(t, "example.com", q.Get("domain_hint"))
	require.Equal(t, "user@example.com", q.Get("login_hint"))
	require.Equal(t, "challenge_value", q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
}

func TestGetSSOPKCEAuthorizationURL_GeneratesPKCE(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	result, err := client.GetSSOPKCEAuthorizationURL(workos.SSOAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Code verifier should be a non-empty string (43+ chars)
	require.NotEmpty(t, result.CodeVerifier)
	require.GreaterOrEqual(t, len(result.CodeVerifier), 43)

	// State should be auto-generated (non-empty)
	require.NotEmpty(t, result.State)

	// URL should contain PKCE parameters
	parsed, err := url.Parse(result.URL)
	require.NoError(t, err)

	q := parsed.Query()
	require.NotEmpty(t, q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, result.State, q.Get("state"))
	require.Equal(t, "/sso/authorize", parsed.Path)
}

func TestGetSSOPKCEAuthorizationURL_PreservesCustomState(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	customState := "my_sso_state"
	result, err := client.GetSSOPKCEAuthorizationURL(workos.SSOAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
		State:       &customState,
	})
	require.NoError(t, err)
	require.Equal(t, "my_sso_state", result.State)
}

func TestSSOPKCECodeExchange_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/sso/token", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"token_type": "Bearer",
			"access_token": "sso_access_tok_abc",
			"expires_in": 3600,
			"profile": {
				"id": "prof_123",
				"connection_id": "conn_456",
				"connection_type": "GoogleOAuth",
				"email": "test@example.com",
				"first_name": "Test",
				"last_name": "User",
				"idp_id": "idp_789",
				"object": "profile",
				"raw_attributes": {}
			}
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL(server.URL),
	)

	result, err := client.SSOPKCECodeExchange(context.Background(), workos.SSOPKCECodeExchangeParams{
		Code:         "auth_code_xyz",
		CodeVerifier: "verifier_abc",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "sso_access_tok_abc", result.AccessToken)
	require.Equal(t, "Bearer", result.TokenType)
}

func TestSSOLogout_WithMockServer(t *testing.T) {
	// The SSOLogout helper first calls AuthorizeLogout (POST /sso/logout/authorize)
	// to get a logout token, then builds the logout redirect URL.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/sso/logout/authorize", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"logout_url": "https://api.workos.com/sso/logout?token=tok_abc",
			"logout_token": "tok_abc"
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL(server.URL),
	)

	returnTo := "https://example.com/signed-out"
	logoutURL, err := client.SSOLogout(context.Background(), workos.SSOLogoutParams{
		SessionID: "sess_123",
		ReturnTo:  &returnTo,
	})
	require.NoError(t, err)
	require.NotEmpty(t, logoutURL)

	parsed, err := url.Parse(logoutURL)
	require.NoError(t, err)

	q := parsed.Query()
	require.Equal(t, "tok_abc", q.Get("token"))
	require.Equal(t, "https://example.com/signed-out", q.Get("return_to"))
}

func TestSSOLogout_WithoutReturnTo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"logout_url": "https://api.workos.com/sso/logout?token=tok_abc",
			"logout_token": "tok_abc"
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL(server.URL),
	)

	logoutURL, err := client.SSOLogout(context.Background(), workos.SSOLogoutParams{
		SessionID: "sess_123",
	})
	require.NoError(t, err)

	parsed, err := url.Parse(logoutURL)
	require.NoError(t, err)

	q := parsed.Query()
	require.Equal(t, "tok_abc", q.Get("token"))
	require.Empty(t, q.Get("return_to"))
}
