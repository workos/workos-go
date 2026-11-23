// @oagen-ignore-file

package workos

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for the methods that send the API key as client_secret. A client
// with an API key sends it, a public client leaves the field out, and a
// workload identity client is refused before anything is sent. They use the
// mock token endpoint and mock API of workload_identity_test.go.

const ssoTokenResponse = `{
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
}`

const authenticateResponse = `{
	"user": {"id": "user_123", "email": "test@example.com"},
	"access_token": "access_tok_abc",
	"refresh_token": "refresh_tok_def"
}`

// clientSecretRefusal is the error a workload identity client gets from the
// named method.
func clientSecretRefusal(method string) string {
	return "workos: " + method + " needs an API key: this request sends it as the client secret. A client that authenticates with workload identity has no API key, so use a client built with one for this call."
}

// respondWith answers every request to the mock API with the JSON body.
func respondWith(body string) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, body)
	}
}

// sentBody decodes the JSON body of the nth request the mock API received.
func sentBody(t *testing.T, api *apiMock, n int) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(api.request(n).body, &body))
	return body
}

func TestClientSecret_APIKeyClientGetsTheKey(t *testing.T) {
	secret, err := NewClient("sk_test_static").clientSecret("AuthenticateWithPassword")

	require.NoError(t, err)
	require.Equal(t, "sk_test_static", secret)
}

func TestClientSecret_PublicClientGetsNoSecret(t *testing.T) {
	cases := map[string]*Client{
		"NewClient without an API key": NewClient("", WithClientID("client_123")),
		"its own HTTP transport":       NewClient("", WithHTTPClient(&http.Client{Transport: &countingTransport{}})),
		"NewPublicClient":              NewPublicClient("client_123").client,
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			secret, err := client.clientSecret("AuthenticateWithCode")

			require.NoError(t, err)
			require.Empty(t, secret)
		})
	}
}

func TestClientSecret_WorkloadIdentityClientIsRefused(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	var providerCalls atomic.Int32
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", &providerCalls))

	cases := map[string]*Client{
		"default HTTP client": newWIFClient(creds, api),
		"WithHTTPClient":      newWIFClient(creds, api, WithHTTPClient(&http.Client{Transport: &countingTransport{}})),
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			secret, err := client.clientSecret("AuthenticateWithPassword")

			require.EqualError(t, err, clientSecretRefusal("AuthenticateWithPassword"))
			require.Empty(t, secret)
		})
	}
	require.Zero(t, providerCalls.Load(), "provider count")
	require.Zero(t, endpoint.count(), "exchange count")
	require.Zero(t, api.count(), "API requests")
}

func TestSSOPKCECodeExchange_WorkloadIdentityClientIsRefusedBeforeAnyRequest(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, respondWith(ssoTokenResponse))
	var providerCalls atomic.Int32
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", &providerCalls))
	client := newWIFClient(creds, api, WithClientID("client_123"))

	result, err := client.SSOPKCECodeExchange(context.Background(), SSOPKCECodeExchangeParams{
		Code:         "auth_code_xyz",
		CodeVerifier: "verifier_abc",
	})

	require.EqualError(t, err, clientSecretRefusal("SSOPKCECodeExchange"))
	require.Nil(t, result)
	require.Zero(t, providerCalls.Load(), "provider count")
	require.Zero(t, endpoint.count(), "exchange count")
	require.Zero(t, api.count(), "API requests")
}

func TestSSOPKCECodeExchange_APIKeyClientSendsTheKeyAsClientSecret(t *testing.T) {
	api := newAPIMock(t, respondWith(ssoTokenResponse))
	client := NewClient("sk_test_static", WithClientID("client_123"), WithBaseURL(api.server.URL))

	result, err := client.SSOPKCECodeExchange(context.Background(), SSOPKCECodeExchangeParams{
		Code:         "auth_code_xyz",
		CodeVerifier: "verifier_abc",
	})

	require.NoError(t, err)
	require.Equal(t, "sso_access_tok_abc", result.AccessToken)
	require.Equal(t, 1, api.count(), "API requests")
	require.Equal(t, map[string]any{
		"grant_type":    "authorization_code",
		"code":          "auth_code_xyz",
		"code_verifier": "verifier_abc",
		"client_id":     "client_123",
		"client_secret": "sk_test_static",
	}, sentBody(t, api, 1))
}

// A public client has a client ID and no API key. Its PKCE flows send the
// code verifier and no client secret: the SSO exchange through the
// hand-written helper, the AuthKit exchange through the generated
// AuthenticateWithCode.
func TestPKCECodeExchange_PublicClientSendsNoClientSecret(t *testing.T) {
	t.Run("SSO", func(t *testing.T) {
		api := newAPIMock(t, respondWith(ssoTokenResponse))
		client := NewClient("", WithClientID("client_123"), WithBaseURL(api.server.URL))

		authorization, err := client.GetSSOPKCEAuthorizationURL(SSOAuthorizationURLParams{
			RedirectURI: "https://example.com/callback",
		})
		require.NoError(t, err)
		result, err := client.SSOPKCECodeExchange(context.Background(), SSOPKCECodeExchangeParams{
			Code:         "auth_code_xyz",
			CodeVerifier: authorization.CodeVerifier,
		})

		require.NoError(t, err)
		require.Equal(t, "sso_access_tok_abc", result.AccessToken)
		require.Equal(t, 1, api.count(), "API requests")
		sent := api.request(1)
		require.Equal(t, "/sso/token", sent.path)
		require.Empty(t, sent.header.Values("Authorization"))
		require.Equal(t, map[string]any{
			"grant_type":    "authorization_code",
			"code":          "auth_code_xyz",
			"code_verifier": authorization.CodeVerifier,
			"client_id":     "client_123",
		}, sentBody(t, api, 1))
	})

	t.Run("AuthKit", func(t *testing.T) {
		api := newAPIMock(t, respondWith(authenticateResponse))
		client := NewClient("", WithClientID("client_123"), WithBaseURL(api.server.URL))

		authorization, err := client.GetAuthKitPKCEAuthorizationURL(AuthKitAuthorizationURLParams{
			RedirectURI: "https://example.com/callback",
		})
		require.NoError(t, err)
		result, err := client.AuthKitPKCECodeExchange(context.Background(), AuthKitPKCECodeExchangeParams{
			Code:         "auth_code_xyz",
			CodeVerifier: authorization.CodeVerifier,
		})

		require.NoError(t, err)
		require.Equal(t, "access_tok_abc", result.AccessToken)
		require.Equal(t, 1, api.count(), "API requests")
		sent := api.request(1)
		require.Equal(t, "/user_management/authenticate", sent.path)
		require.Empty(t, sent.header.Values("Authorization"))
		require.Equal(t, map[string]any{
			"grant_type":    "authorization_code",
			"code":          "auth_code_xyz",
			"code_verifier": authorization.CodeVerifier,
			"client_id":     "client_123",
		}, sentBody(t, api, 1))
	})
}
