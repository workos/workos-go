// @oagen-ignore-file

package workos_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6"
)

func TestNewPublicClient_CreatesClient(t *testing.T) {
	pc := workos.NewPublicClient("client_123")
	require.NotNil(t, pc)
}

func TestNewPublicClient_WithCustomBaseURL(t *testing.T) {
	pc := workos.NewPublicClient("client_123",
		workos.WithPublicClientBaseURL("https://custom.workos.dev"),
	)
	require.NotNil(t, pc)

	// Verify the custom base URL is used in generated URLs
	result, err := pc.GetAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
	})
	require.NoError(t, err)

	parsed, err := url.Parse(result.URL)
	require.NoError(t, err)
	require.Equal(t, "custom.workos.dev", parsed.Host)
}

func TestPublicClient_GetAuthorizationURL_GeneratesPKCE(t *testing.T) {
	pc := workos.NewPublicClient("client_123")

	result, err := pc.GetAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have a code verifier (43+ chars)
	require.NotEmpty(t, result.CodeVerifier)
	require.GreaterOrEqual(t, len(result.CodeVerifier), 43)

	// Should have auto-generated state
	require.NotEmpty(t, result.State)

	// URL should contain the correct parameters
	parsed, err := url.Parse(result.URL)
	require.NoError(t, err)
	require.Equal(t, "/user_management/authorize", parsed.Path)

	q := parsed.Query()
	require.Equal(t, "client_123", q.Get("client_id"))
	require.Equal(t, "https://example.com/callback", q.Get("redirect_uri"))
	require.Equal(t, "code", q.Get("response_type"))
	require.NotEmpty(t, q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, result.State, q.Get("state"))
}

func TestPublicClient_GetAuthorizationURL_PreservesCustomState(t *testing.T) {
	pc := workos.NewPublicClient("client_123")

	customState := "my_public_state"
	result, err := pc.GetAuthorizationURL(workos.AuthKitAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
		State:       &customState,
	})
	require.NoError(t, err)
	require.Equal(t, "my_public_state", result.State)
}

func TestPublicClient_GetAuthorizationURL_FailsWithoutRedirectURI(t *testing.T) {
	pc := workos.NewPublicClient("client_123")

	_, err := pc.GetAuthorizationURL(workos.AuthKitAuthorizationURLParams{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "redirect_uri is required")
}

func TestPublicClient_GetSSOAuthorizationURL_GeneratesPKCE(t *testing.T) {
	pc := workos.NewPublicClient("client_123")

	result, err := pc.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have a code verifier (43+ chars)
	require.NotEmpty(t, result.CodeVerifier)
	require.GreaterOrEqual(t, len(result.CodeVerifier), 43)

	// Should have auto-generated state
	require.NotEmpty(t, result.State)

	// URL should point to SSO authorize endpoint
	parsed, err := url.Parse(result.URL)
	require.NoError(t, err)
	require.Equal(t, "/sso/authorize", parsed.Path)

	q := parsed.Query()
	require.Equal(t, "client_123", q.Get("client_id"))
	require.Equal(t, "https://example.com/callback", q.Get("redirect_uri"))
	require.Equal(t, "code", q.Get("response_type"))
	require.NotEmpty(t, q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, result.State, q.Get("state"))
}

func TestPublicClient_GetSSOAuthorizationURL_PreservesCustomState(t *testing.T) {
	pc := workos.NewPublicClient("client_123")

	customState := "my_sso_public_state"
	result, err := pc.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{
		RedirectURI: "https://example.com/callback",
		State:       &customState,
	})
	require.NoError(t, err)
	require.Equal(t, "my_sso_public_state", result.State)
}

func TestPublicClient_GetSSOAuthorizationURL_FailsWithoutRedirectURI(t *testing.T) {
	pc := workos.NewPublicClient("client_123")

	_, err := pc.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "redirect_uri is required")
}
