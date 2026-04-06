// @oagen-ignore-file

package workos_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6"
)

func TestGetAuthKitAuthorizationURL_BuildsCorrectURL(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	provider := "GoogleOAuth"
	state := "custom_state"
	result, err := client.GetAuthKitAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
		Provider:    &provider,
		State:       &state,
	})
	require.NoError(t, err)

	parsed, err := url.Parse(result)
	require.NoError(t, err)

	require.Equal(t, "https", parsed.Scheme)
	require.Equal(t, "api.workos.com", parsed.Host)
	require.Equal(t, "/user_management/authorize", parsed.Path)

	q := parsed.Query()
	require.Equal(t, "client_123", q.Get("client_id"))
	require.Equal(t, "https://example.com/callback", q.Get("redirect_uri"))
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "GoogleOAuth", q.Get("provider"))
	require.Equal(t, "custom_state", q.Get("state"))
}

func TestGetAuthKitAuthorizationURL_AllOptionalParams(t *testing.T) {
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
	screenHint := "sign-up"

	result, err := client.GetAuthKitAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI:         "https://example.com/callback",
		Provider:            &provider,
		ConnectionID:        &connectionID,
		OrganizationID:      &organizationID,
		DomainHint:          &domainHint,
		LoginHint:           &loginHint,
		State:               &state,
		CodeChallenge:       &codeChallenge,
		CodeChallengeMethod: &codeChallengeMethod,
		ScreenHint:          &screenHint,
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
	require.Equal(t, "sign-up", q.Get("screen_hint"))
}

func TestGetAuthKitAuthorizationURL_FailsWithoutRedirectURI(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
	)

	_, err := client.GetAuthKitAuthorizationURL(workos.AuthKitAuthorizationURLParams{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "redirect_uri is required")
}

func TestGetAuthKitAuthorizationURL_FailsWithoutClientID(t *testing.T) {
	client := workos.NewClient("sk_test")

	_, err := client.GetAuthKitAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_id is required")
}

func TestGetAuthKitAuthorizationURL_UsesParamClientIDOverConfigured(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("configured_client"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	result, err := client.GetAuthKitAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
		ClientID:    "param_client",
	})
	require.NoError(t, err)

	parsed, err := url.Parse(result)
	require.NoError(t, err)
	require.Equal(t, "param_client", parsed.Query().Get("client_id"))
}

func TestGetAuthKitPKCEAuthorizationURL_GeneratesPKCEAndState(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	result, err := client.GetAuthKitPKCEAuthorizationURL(workos.AuthKitAuthorizationURLParams{
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
}

func TestGetAuthKitPKCEAuthorizationURL_PreservesCustomState(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	customState := "my_custom_state"
	result, err := client.GetAuthKitPKCEAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
		State:       &customState,
	})
	require.NoError(t, err)
	require.Equal(t, "my_custom_state", result.State)

	parsed, err := url.Parse(result.URL)
	require.NoError(t, err)
	require.Equal(t, "my_custom_state", parsed.Query().Get("state"))
}

func TestAuthKitPKCECodeExchange_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/user_management/authenticate", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"user": {"id": "user_123", "email": "test@example.com"},
			"access_token": "access_tok_abc",
			"refresh_token": "refresh_tok_def"
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test",
		workos.WithClientID("client_123"),
		workos.WithBaseURL(server.URL),
	)

	result, err := client.AuthKitPKCECodeExchange(context.Background(), workos.AuthKitPKCECodeExchangeParams{
		Code:         "auth_code_xyz",
		CodeVerifier: "verifier_abc",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "access_tok_abc", result.AccessToken)
	require.Equal(t, "refresh_tok_def", result.RefreshToken)
}
