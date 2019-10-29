package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientAuthorizeURL(t *testing.T) {
	tests := []struct {
		scenario string
		options  GetAuthorizationURLOptions
		expected string
	}{
		{
			scenario: "generate url",
			options: GetAuthorizationURLOptions{
				Domain:      "lyft.com",
				RedirectURI: "https://example.com/sso/workos/callback",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=proj_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code",
		},
		{
			scenario: "generate url with state",
			options: GetAuthorizationURLOptions{
				Domain:      "lyft.com",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=proj_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client := Client{
				APIKey:    "test",
				ProjectID: "proj_123",
			}

			u, err := client.GetAuthorizationURL(test.options)
			require.NoError(t, err)
			require.Equal(t, test.expected, u.String())
		})
	}
}

func TestClientGetProfile(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetProfileOptions
		expected Profile
		err      bool
	}{
		{
			scenario: "request without api key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "request returns a profile",
			client: &Client{
				APIKey:    "test",
				ProjectID: "proj_123",
			},
			options: GetProfileOptions{
				Code:        "authorization_code",
				RedirectURI: "https://exmaple.com/sso/workos/callback",
			},
			expected: Profile{
				ID:             "proj_123",
				IdpID:          "123",
				ConnectionType: OktaSAML,
				Email:          "foo@test.com",
				FirstName:      "foo",
				LastName:       "bar",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(profileTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			profile, err := client.GetProfile(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, profile)
		})
	}
}

func profileTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/sso/token" {
		fmt.Println("path:", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if auth := r.Header.Get("Authorization"); auth != "Bearer test" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if contentType := r.Header.Get("Content-Type"); contentType != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	b, err := json.Marshal(Profile{
		ID:             "proj_123",
		IdpID:          "123",
		ConnectionType: OktaSAML,
		Email:          "foo@test.com",
		FirstName:      "foo",
		LastName:       "bar",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(b)
}
