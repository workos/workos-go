package sso

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientAuthorizeURL(t *testing.T) {
	tests := []struct {
		scenario string
		options  AuthorizationURLOptions
		expected string
	}{
		{
			scenario: "generate url",
			options: AuthorizationURLOptions{
				Domain:      "lyft.com",
				ProjectID:   "proj_123",
				RedirectURI: "https://example.com/sso/workos/callback",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=proj_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code",
		},
		{
			scenario: "generate url with state",
			options: AuthorizationURLOptions{
				Domain:      "lyft.com",
				ProjectID:   "proj_123",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=proj_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client := Client{}
			u, err := client.AuthorizationURL(test.options)
			require.NoError(t, err)
			require.Equal(t, test.expected, u.String())
		})
	}
}
