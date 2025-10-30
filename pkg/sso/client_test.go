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
	"github.com/workos/workos-go/v5/pkg/common"
)

func TestClientAuthorizeURL(t *testing.T) {
	tests := []struct {
		scenario string
		options  GetAuthorizationURLOpts
		expected string
	}{
		{
			scenario: "generate url",
			options: GetAuthorizationURLOpts{
				Domain:      "lyft.com",
				RedirectURI: "https://example.com/sso/workos/callback",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code",
		},
		{
			scenario: "generate url with state",
			options: GetAuthorizationURLOpts{
				Domain:      "lyft.com",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with provider",
			options: GetAuthorizationURLOpts{
				Provider:    "GoogleOAuth",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&provider=GoogleOAuth&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with connection",
			options: GetAuthorizationURLOpts{
				Connection:  "connection_123",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&connection=connection_123&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with provider and domain",
			options: GetAuthorizationURLOpts{
				Domain:      "lyft.com",
				Provider:    "GoogleOAuth",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&domain=lyft.com&provider=GoogleOAuth&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with organization",
			options: GetAuthorizationURLOpts{
				Organization: "organization_123",
				RedirectURI:  "https://example.com/sso/workos/callback",
				State:        "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&organization=organization_123&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with DomainHint",
			options: GetAuthorizationURLOpts{
				Connection:  "connection_123",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
				DomainHint:  "foo.com",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&connection=connection_123&domain_hint=foo.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with LoginHint",
			options: GetAuthorizationURLOpts{
				Connection:  "connection_123",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
				LoginHint:   "foo@workos.com",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&connection=connection_123&login_hint=foo%40workos.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client := Client{
				APIKey:   "test",
				ClientID: "client_123",
			}

			u, err := client.GetAuthorizationURL(test.options)
			require.NoError(t, err)
			require.Equal(t, test.expected, u.String())
		})
	}
}

func TestClientAuthorizeURLWithNoConnectionDomainAndProvider(t *testing.T) {
	client := Client{
		APIKey:   "test",
		ClientID: "client_123",
	}

	u, err := client.GetAuthorizationURL(GetAuthorizationURLOpts{
		RedirectURI: "https://example.com/sso/workos/callback",
		State:       "state",
	})

	require.Error(t, err)
	require.Nil(t, u)
}

func TestClientGetProfileAndToken(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetProfileAndTokenOpts
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
				APIKey:   "test",
				ClientID: "client_123",
			},
			options: GetProfileAndTokenOpts{
				Code: "authorization_code",
			},
			expected: Profile{
				ID:             "profile_123",
				IdpID:          "123",
				OrganizationID: "org_123",
				ConnectionID:   "conn_123",
				ConnectionType: OktaSAML,
				Email:          "foo@test.com",
				FirstName:      "foo",
				LastName:       "bar",
				Role: common.RoleResponse{
					Slug: "admin",
				},
				Groups: []string{"Admins", "Developers"},
				CustomAttributes: map[string]interface{}{
					"license": "professional",
				},
				RawAttributes: map[string]interface{}{
					"idp_id":     "123",
					"email":      "foo@test.com",
					"first_name": "foo",
					"last_name":  "bar",
					"license":    "professional",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(profileAndTokenTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			profileAndToken, err := client.GetProfileAndToken(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, profileAndToken.Profile)
		})
	}
}

func profileAndTokenTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/sso/token" {
		fmt.Println("path:", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	r.ParseForm()

	if clientSecret := r.Form.Get("client_secret"); clientSecret != "test" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	b, err := json.Marshal(struct {
		Profile Profile `json:"profile"`
	}{
		Profile: Profile{
			ID:             "profile_123",
			IdpID:          "123",
			OrganizationID: "org_123",
			ConnectionID:   "conn_123",
			ConnectionType: OktaSAML,
			Email:          "foo@test.com",
			FirstName:      "foo",
			LastName:       "bar",
			Role: common.RoleResponse{
				Slug: "admin",
			},
			Groups: []string{"Admins", "Developers"},
			CustomAttributes: map[string]interface{}{
				"license": "professional",
			},
			RawAttributes: map[string]interface{}{
				"idp_id":     "123",
				"email":      "foo@test.com",
				"first_name": "foo",
				"last_name":  "bar",
				"license":    "professional",
			},
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func TestClientGetProfile(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetProfileOpts
		expected Profile
		err      bool
	}{
		{
			scenario: "request returns a profile",
			client: &Client{
				APIKey:   "test",
				ClientID: "client_123",
			},
			options: GetProfileOpts{
				AccessToken: "access_token",
			},
			expected: Profile{
				ID:             "profile_123",
				IdpID:          "123",
				OrganizationID: "org_123",
				ConnectionID:   "conn_123",
				ConnectionType: OktaSAML,
				Email:          "foo@test.com",
				FirstName:      "foo",
				LastName:       "bar",
				Role: common.RoleResponse{
					Slug: "admin",
				},
				Groups: []string{"Admins", "Developers"},
				CustomAttributes: map[string]interface{}{
					"license": "professional",
				},
				RawAttributes: map[string]interface{}{
					"idp_id":     "123",
					"email":      "foo@test.com",
					"first_name": "foo",
					"last_name":  "bar",
					"license":    "professional",
				},
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
	if r.URL.Path != "/sso/profile" {
		fmt.Println("path:", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	b, err := json.Marshal(Profile{
		ID:             "profile_123",
		IdpID:          "123",
		OrganizationID: "org_123",
		ConnectionID:   "conn_123",
		ConnectionType: OktaSAML,
		Email:          "foo@test.com",
		FirstName:      "foo",
		LastName:       "bar",
		Role: common.RoleResponse{
			Slug: "admin",
		},
		Groups: []string{"Admins", "Developers"},
		CustomAttributes: map[string]interface{}{
			"license": "professional",
		},
		RawAttributes: map[string]interface{}{
			"idp_id":     "123",
			"email":      "foo@test.com",
			"first_name": "foo",
			"last_name":  "bar",
			"license":    "professional",
		},
	},
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func TestGetConnection(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetConnectionOpts
		expected Connection
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns a Connection",
			client: &Client{
				APIKey: "test",
			},
			options: GetConnectionOpts{
				Connection: "connection_id",
			},
			expected: Connection{
				ID:             "conn_id",
				ConnectionType: "GoogleOAuth",
				State:          Active,
				Status:         Linked,
				Name:           "Foo Corp",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getConnectionTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			connection, err := client.GetConnection(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, connection)
		})
	}
}

func getConnectionTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(Connection{
		ID:             "conn_id",
		ConnectionType: "GoogleOAuth",
		State:          Active,
		Status:         Linked,
		Name:           "Foo Corp",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListConnections(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListConnectionsOpts
		expected ListConnectionsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Connections",
			client: &Client{
				APIKey: "test",
			},
			options: ListConnectionsOpts{},
			expected: ListConnectionsResponse{
				Data: []Connection{
					Connection{
						ID:             "conn_id",
						ConnectionType: "GoogleOAuth",
						State:          Active,
						Status:         Linked,
						Name:           "Foo Corp",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listConnectionsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			connections, err := client.ListConnections(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, connections)
		})
	}
}

func listConnectionsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListConnectionsResponse{
		Data: []Connection{
			Connection{
				ID:             "conn_id",
				ConnectionType: "GoogleOAuth",
				State:          Active,
				Status:         Linked,
				Name:           "Foo Corp",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListConnections_UnmarshalSnakeCaseListMetadata(t *testing.T) {
	raw := []byte(`{
        "data": [],
        "list_metadata": { "before": "", "after": "conn_abc123" }
    }`)

	var resp ListConnectionsResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.Equal(t, "conn_abc123", resp.ListMetadata.After)
	require.Equal(t, "", resp.ListMetadata.Before)
}
