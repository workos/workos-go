// @oagen-ignore-file

package workos_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v8"
)

func TestGetJWKSURL_BuildsCorrectURL(t *testing.T) {
	result := workos.GetJWKSURL("https://api.workos.com", "client_123")
	require.Equal(t, "https://api.workos.com/sso/jwks/client_123", result)
}

func TestGetJWKSURL_UsesDefaultBaseURL(t *testing.T) {
	result := workos.GetJWKSURL("", "client_456")
	require.Equal(t, "https://api.workos.com/sso/jwks/client_456", result)
}

func TestGetJWKSURL_CustomBaseURL(t *testing.T) {
	result := workos.GetJWKSURL("https://custom.workos.dev", "client_789")
	require.Equal(t, "https://custom.workos.dev/sso/jwks/client_789", result)
}

func TestJWKSURLFromClient_UsesClientConfig(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_abc"),
		workos.WithBaseURL("https://api.workos.com"),
	)

	result := client.JWKSURLFromClient()
	require.Equal(t, "https://api.workos.com/sso/jwks/client_abc", result)
}

func TestJWKSURLFromClient_CustomBaseURL(t *testing.T) {
	client := workos.NewClient("sk_test",
		workos.WithClientID("client_def"),
		workos.WithBaseURL("https://staging.workos.dev"),
	)

	result := client.JWKSURLFromClient()
	require.Equal(t, "https://staging.workos.dev/sso/jwks/client_def", result)
}
