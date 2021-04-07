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
	"github.com/workos-inc/workos-go/pkg/common"
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
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code",
		},
		{
			scenario: "generate url with state",
			options: GetAuthorizationURLOptions{
				Domain:      "lyft.com",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&domain=lyft.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with provider",
			options: GetAuthorizationURLOptions{
				Provider:    "GoogleOAuth",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&provider=GoogleOAuth&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with connection",
			options: GetAuthorizationURLOptions{
				Connection:  "connection_123",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&connection=connection_123&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with provider and domain",
			options: GetAuthorizationURLOptions{
				Domain:      "lyft.com",
				Provider:    "GoogleOAuth",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/sso/authorize?client_id=client_123&domain=lyft.com&provider=GoogleOAuth&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
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

	u, err := client.GetAuthorizationURL(GetAuthorizationURLOptions{
		RedirectURI: "https://example.com/sso/workos/callback",
		State:       "state",
	})

	require.Error(t, err)
	require.Nil(t, u)
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
				APIKey:   "test",
				ClientID: "client_123",
			},
			options: GetProfileOptions{
				Code: "authorization_code",
			},
			expected: Profile{
				ID:             "profile_123",
				IdpID:          "123",
				ConnectionID:   "conn_123",
				ConnectionType: OktaSAML,
				Email:          "foo@test.com",
				FirstName:      "foo",
				LastName:       "bar",
				RawAttributes: map[string]interface{}{
					"idp_id":     "123",
					"email":      "foo@test.com",
					"first_name": "foo",
					"last_name":  "bar",
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
			ConnectionID:   "conn_123",
			ConnectionType: OktaSAML,
			Email:          "foo@test.com",
			FirstName:      "foo",
			LastName:       "bar",
			RawAttributes: map[string]interface{}{
				"idp_id":     "123",
				"email":      "foo@test.com",
				"first_name": "foo",
				"last_name":  "bar",
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

func TestPromoteDraftConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(promoteDraftConnectionTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:   "test",
		Endpoint: server.URL,
	}

	err := client.PromoteDraftConnection(context.TODO(), PromoteDraftConnectionOptions{
		Token: "wOrkOStoKeN",
	})
	require.NoError(t, err)
}

func TestPromoteDraftConnectionUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(promoteDraftConnectionTestHandler))
	defer server.Close()

	client := &Client{
		Endpoint: server.URL,
	}

	err := client.PromoteDraftConnection(context.TODO(), PromoteDraftConnectionOptions{
		Token: "wOrkOStoKeN",
	})
	require.Error(t, err)
	t.Log(err)
}

func TestPromoteDraftBadToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(promoteDraftConnectionTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:   "test",
		Endpoint: server.URL,
	}

	err := client.PromoteDraftConnection(context.TODO(), PromoteDraftConnectionOptions{
		Token: "wOrkOStoKeNfoo",
	})
	require.Error(t, err)
	t.Log(err)
}

func promoteDraftConnectionTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	userAgent := r.Header.Get("User-Agent")
	if !strings.HasPrefix(userAgent, "workos-go/") {
		http.Error(w, "bad user agent", http.StatusBadRequest)
		return
	}

	path := strings.Split(r.URL.Path, "/")

	if len(path) != 4 {
		http.Error(w, "path does not have 3 elements", http.StatusNotFound)
		return
	}

	if path[1] != "draft_connections" || path[3] != "activate" {
		http.Error(w, "invalid path: "+r.URL.Path, http.StatusNotFound)
		return
	}

	if token := path[2]; token != "wOrkOStoKeN" {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func TestClientCreateConnection(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateConnectionOpts
		expected Connection
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request with valid API Key and Draft Connection",
			client: &Client{
				APIKey: "test",
			},
			options: CreateConnectionOpts{
				Source: "source",
			},
			expected: Connection{
				ID:                        "connection",
				Name:                      "Terrace House",
				Status:                    Unlinked,
				ConnectionType:            OktaSAML,
				OAuthUID:                  "",
				OAuthSecret:               "",
				OAuthRedirectURI:          "",
				SamlEntityID:              "http://www.okta.com/rijeonghyeok",
				SamlIDPURL:                "https://foo.okta.com/app/fried/chicken/sso/saml",
				SamlRelyingPartyTrustCert: "",
				SamlX509Certs: []string{
					"-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
				},
			},
			err: false,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createConnectionTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			connection, err := client.CreateConnection(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, connection)
		})
	}
}

func createConnectionTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/connections" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	connection, err := json.Marshal(Connection{
		ID:                        "connection",
		Name:                      "Terrace House",
		Status:                    Unlinked,
		ConnectionType:            OktaSAML,
		OAuthUID:                  "",
		OAuthSecret:               "",
		OAuthRedirectURI:          "",
		SamlEntityID:              "http://www.okta.com/rijeonghyeok",
		SamlIDPURL:                "https://foo.okta.com/app/fried/chicken/sso/saml",
		SamlRelyingPartyTrustCert: "",
		SamlX509Certs: []string{
			"-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
		},
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(connection)
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
				ID:                        "conn_id",
				ConnectionType:            "GoogleOAuth",
				Name:                      "Foo Corp",
				OAuthRedirectURI:          "uri",
				OAuthSecret:               "secret",
				OAuthUID:                  "uid",
				SamlEntityID:              "null",
				SamlIDPURL:                "null",
				SamlRelyingPartyTrustCert: "null",
				SamlX509Certs:             []string{},
				Status:                    "linked",
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
		ID:                        "conn_id",
		ConnectionType:            "GoogleOAuth",
		Name:                      "Foo Corp",
		OAuthRedirectURI:          "uri",
		OAuthSecret:               "secret",
		OAuthUID:                  "uid",
		SamlEntityID:              "null",
		SamlIDPURL:                "null",
		SamlRelyingPartyTrustCert: "null",
		SamlX509Certs:             []string{},
		Status:                    "linked",
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
						ID:                        "conn_id",
						ConnectionType:            "GoogleOAuth",
						Name:                      "Foo Corp",
						OAuthRedirectURI:          "uri",
						OAuthSecret:               "secret",
						OAuthUID:                  "uid",
						SamlEntityID:              "null",
						SamlIDPURL:                "null",
						SamlRelyingPartyTrustCert: "null",
						SamlX509Certs:             []string{},
						Status:                    "linked",
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
				ID:                        "conn_id",
				ConnectionType:            "GoogleOAuth",
				Name:                      "Foo Corp",
				OAuthRedirectURI:          "uri",
				OAuthSecret:               "secret",
				OAuthUID:                  "uid",
				SamlEntityID:              "null",
				SamlIDPURL:                "null",
				SamlRelyingPartyTrustCert: "null",
				SamlX509Certs:             []string{},
				Status:                    "linked",
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
