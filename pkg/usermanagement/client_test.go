package usermanagement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
	"github.com/workos/workos-go/v4/pkg/mfa"
)

func TestGetUser(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetUserOpts
		expected User
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns a User",
			client:   NewClient("test"),
			options: GetUserOpts{
				User: "user_123",
			},
			expected: User{
				ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				Email:         "marcelina@foo-corp.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: true,
				CreatedAt:     "2021-06-25T19:07:33.155Z",
				UpdatedAt:     "2021-06-25T19:07:33.155Z",
			},
		},
		{
			scenario: "Request returns a User with an unmarshalled `ProfilePictureURL`",
			client:   NewClient("test"),
			options: GetUserOpts{
				User: "user_456",
			},
			expected: User{
				ID:                "user_01E3JC5F5Z1YJNPGVYWV9SX456",
				Email:             "marcelina@foo-corp.com",
				FirstName:         "Marcelina",
				LastName:          "Davis",
				EmailVerified:     true,
				ProfilePictureURL: "https://workoscdn.com/images/v1/123abc",
				CreatedAt:         "2021-06-25T19:07:33.155Z",
				UpdatedAt:         "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getUserTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.GetUser(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func getUserTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users/user_123" {
		body, err = json.Marshal(User{
			ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
			CreatedAt:     "2021-06-25T19:07:33.155Z",
			UpdatedAt:     "2021-06-25T19:07:33.155Z",
		})
	}

	if r.URL.Path == "/user_management/users/user_456" {
		body, err = json.Marshal(User{
			ID:                "user_01E3JC5F5Z1YJNPGVYWV9SX456",
			Email:             "marcelina@foo-corp.com",
			FirstName:         "Marcelina",
			LastName:          "Davis",
			EmailVerified:     true,
			ProfilePictureURL: "https://workoscdn.com/images/v1/123abc",
			CreatedAt:         "2021-06-25T19:07:33.155Z",
			UpdatedAt:         "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListUsers(t *testing.T) {
	t.Run("ListUsers succeeds to fetch Users", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(listUsersTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		expectedResponse := ListUsersResponse{
			Data: []User{
				{
					ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					Email:         "marcelina@foo-corp.com",
					FirstName:     "Marcelina",
					LastName:      "Davis",
					EmailVerified: true,
					CreatedAt:     "2021-06-25T19:07:33.155Z",
					UpdatedAt:     "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		}

		users, err := client.ListUsers(context.Background(), ListUsersOpts{})

		require.NoError(t, err)
		require.Equal(t, expectedResponse, users)
	})

	t.Run("ListUsers succeeds to fetch Users belonging to an Organization", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(listUsersTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		expectedResponse := ListUsersResponse{
			Data: []User{
				{
					ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					Email:         "marcelina@foo-corp.com",
					FirstName:     "Marcelina",
					LastName:      "Davis",
					EmailVerified: true,
					CreatedAt:     "2021-06-25T19:07:33.155Z",
					UpdatedAt:     "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		}

		users, err := client.ListUsers(context.Background(), ListUsersOpts{OrganizationID: "org_123"})

		require.NoError(t, err)
		require.Equal(t, expectedResponse, users)
	})

	t.Run("ListUsers succeeds to fetch Users created after a timestamp", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(listUsersTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		currentTime := time.Now()
		after := currentTime.AddDate(0, 0, -2)

		params := ListUsersOpts{
			After: after.String(),
		}

		expectedResponse := ListUsersResponse{
			Data: []User{
				{
					ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					Email:         "marcelina@foo-corp.com",
					FirstName:     "Marcelina",
					LastName:      "Davis",
					EmailVerified: true,
					CreatedAt:     "2021-06-25T19:07:33.155Z",
					UpdatedAt:     "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		}

		users, err := client.ListUsers(context.Background(), params)

		require.NoError(t, err)
		require.Equal(t, expectedResponse, users)
	})
}

func listUsersTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(struct {
		ListUsersResponse
	}{
		ListUsersResponse: ListUsersResponse{
			Data: []User{
				{
					ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					Email:         "marcelina@foo-corp.com",
					FirstName:     "Marcelina",
					LastName:      "Davis",
					EmailVerified: true,
					CreatedAt:     "2021-06-25T19:07:33.155Z",
					UpdatedAt:     "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateUser(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateUserOpts
		expected User
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: CreateUserOpts{
				Email:         "marcelina@gmail.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: false,
				Password:      "pass",
			},
			expected: User{
				ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				Email:         "marcelina@foo-corp.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: true,
				CreatedAt:     "2021-06-25T19:07:33.155Z",
				UpdatedAt:     "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createUserTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.CreateUser(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func createUserTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users" {
		body, err = json.Marshal(User{
			ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
			CreatedAt:     "2021-06-25T19:07:33.155Z",
			UpdatedAt:     "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestUpdateUser(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdateUserOpts
		expected User
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: UpdateUserOpts{
				User:          "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: false,
			},
			expected: User{
				ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				Email:         "marcelina@foo-corp.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: true,
				CreatedAt:     "2021-06-25T19:07:33.155Z",
				UpdatedAt:     "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateUserTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.UpdateUser(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func updateUserTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH" {
		body, err = json.Marshal(User{
			ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
			CreatedAt:     "2021-06-25T19:07:33.155Z",
			UpdatedAt:     "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestDeleteUser(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteUserOpts
		expected error
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: DeleteUserOpts{
				User: "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteUserTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.DeleteUser(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, err)
		})
	}
}

func deleteUserTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH" {
		body, err = nil, nil
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListIdentities(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListIdentitiesOpts
		expected ListIdentitiesResult
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns identities",
			client:   NewClient("test"),
			options: ListIdentitiesOpts{
				ID: "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			},
			expected: ListIdentitiesResult{
				Identities: []Identity{
					{
						IdpID:    "13966412",
						Type:     "OAuth",
						Provider: "GitHubOAuth",
					},
				},
			},
			err: false,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listIdentitiesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			identities, err := client.ListIdentities(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, identities)
		})
	}
}

func listIdentitiesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "bad method", http.StatusBadRequest)
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListIdentitiesResult{
		Identities: []Identity{
			{
				IdpID:    "13966412",
				Type:     "OAuth",
				Provider: "GitHubOAuth",
			},
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestClientAuthorizeURL(t *testing.T) {
	tests := []struct {
		scenario string
		options  GetAuthorizationURLOpts
		expected string
	}{
		{
			scenario: "generate url with provider",
			options: GetAuthorizationURLOpts{
				ClientID:    "client_123",
				Provider:    "GoogleOAuth",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&provider=GoogleOAuth&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with a screen hint",
			options: GetAuthorizationURLOpts{
				ClientID:    "client_123",
				Provider:    "authkit",
				RedirectURI: "https://example.com/sso/workos/callback",
				ScreenHint:  "sign-up",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&provider=authkit&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&screen_hint=sign-up",
		},
		{
			scenario: "generate url with connection",
			options: GetAuthorizationURLOpts{
				ClientID:     "client_123",
				ConnectionID: "connection_123",
				RedirectURI:  "https://example.com/sso/workos/callback",
				State:        "custom state",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&connection_id=connection_123&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with state",
			options: GetAuthorizationURLOpts{
				ClientID:    "client_123",
				Provider:    "GoogleOAuth",
				RedirectURI: "https://example.com/sso/workos/callback",
				State:       "custom state",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&provider=GoogleOAuth&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with provider and connection",
			options: GetAuthorizationURLOpts{
				ClientID:     "client_123",
				ConnectionID: "connection_123",
				Provider:     "GoogleOAuth",
				RedirectURI:  "https://example.com/sso/workos/callback",
				State:        "custom state",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&connection_id=connection_123&provider=GoogleOAuth&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with organization",
			options: GetAuthorizationURLOpts{
				ClientID:       "client_123",
				OrganizationID: "organization_123",
				RedirectURI:    "https://example.com/sso/workos/callback",
				State:          "custom state",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&organization_id=organization_123&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with DomainHint",
			options: GetAuthorizationURLOpts{
				ClientID:     "client_123",
				ConnectionID: "connection_123",
				RedirectURI:  "https://example.com/sso/workos/callback",
				State:        "custom state",
				DomainHint:   "foo.com",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&connection_id=connection_123&domain_hint=foo.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
		{
			scenario: "generate url with LoginHint",
			options: GetAuthorizationURLOpts{
				ClientID:     "client_123",
				ConnectionID: "connection_123",
				RedirectURI:  "https://example.com/sso/workos/callback",
				State:        "custom state",
				LoginHint:    "foo@workos.com",
			},
			expected: "https://api.workos.com/user_management/authorize?client_id=client_123&connection_id=connection_123&login_hint=foo%40workos.com&redirect_uri=https%3A%2F%2Fexample.com%2Fsso%2Fworkos%2Fcallback&response_type=code&state=custom+state",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client := NewClient("test")
			u, err := client.GetAuthorizationURL(test.options)
			require.NoError(t, err)
			require.Equal(t, test.expected, u.String())
		})
	}
}

func TestClientAuthorizeURLInvalidOpts(t *testing.T) {
	tests := []struct {
		scenario string
		options  GetAuthorizationURLOpts
	}{
		{
			scenario: "without selector",
			options: GetAuthorizationURLOpts{
				ClientID:    "client_123",
				RedirectURI: "https://example.com/sso/workos/callback",
			},
		},
		{
			scenario: "without ClientID",
			options: GetAuthorizationURLOpts{
				ConnectionID: "connection_123",
				RedirectURI:  "https://example.com/sso/workos/callback",
			},
		},
		{
			scenario: "without RedirectURI",
			options: GetAuthorizationURLOpts{
				ClientID:     "client_123",
				ConnectionID: "connection_123",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client := NewClient("test")
			u, err := client.GetAuthorizationURL(test.options)
			require.Error(t, err)
			require.Nil(t, u)
		})
	}
}

func TestAuthenticateUserWithPassword(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithPasswordOpts
		expected AuthenticateResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns a User",
			client:   NewClient("test"),
			options: AuthenticateWithPasswordOpts{
				ClientID: "project_123",
				Email:    "employee@foo-corp.com",
				Password: "test_123",
			},
			expected: AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.AuthenticateWithPassword(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func TestAuthenticateUserWithCode(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithCodeOpts
		expected AuthenticateResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns a User",
			client:   NewClient("test"),
			options: AuthenticateWithCodeOpts{
				ClientID: "project_123",
				Code:     "test_123",
			},
			expected: AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
			},
		},
		{
			scenario: "Request returns a User and Impersonator metadata",
			client:   NewClient("test_with_impersonation"),
			options: AuthenticateWithCodeOpts{
				ClientID: "project_123",
				Code:     "test_123",
			},
			expected: AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
				Impersonator: &Impersonator{
					Email:  "admin@example.com",
					Reason: "Helping debug a customer issue.",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.AuthenticateWithCode(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func TestAuthenticateUserWithRefreshToken(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithRefreshTokenOpts
		expected RefreshAuthenticationResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request new tokens",
			client:   NewClient("test"),
			options: AuthenticateWithRefreshTokenOpts{
				ClientID:     "project_123",
				RefreshToken: "refresh_token",
			},
			expected: RefreshAuthenticationResponse{
				AccessToken:  "access_token",
				RefreshToken: "new_refresh_token",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(refreshAuthenticationResponseTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.AuthenticateWithRefreshToken(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func TestAuthenticateUserWithMagicAuth(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithMagicAuthOpts
		expected AuthenticateResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns a User",
			client:   NewClient("test"),
			options: AuthenticateWithMagicAuthOpts{
				ClientID:              "project_123",
				Code:                  "test_123",
				Email:                 "employee@foo-corp.com",
				LinkAuthorizationCode: "test_456",
			},
			expected: AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.AuthenticateWithMagicAuth(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func TestAuthenticateUserWithTOTP(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithTOTPOpts
		expected AuthenticateResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns a User",
			client:   NewClient("test"),
			options: AuthenticateWithTOTPOpts{
				ClientID:                   "project_123",
				Code:                       "test_123",
				PendingAuthenticationToken: "cTDQJTTkTkkVYxQUlKBIxEsFs",
				AuthenticationChallengeID:  "auth_challenge_01H96FETXGTW1QMBSBT2T36PW0",
			},
			expected: AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.AuthenticateWithTOTP(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func TestAuthenticateUserWithEmailVerificationCode(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithEmailVerificationCodeOpts
		expected AuthenticateResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns a User",
			client:   NewClient("test"),
			options: AuthenticateWithEmailVerificationCodeOpts{
				ClientID:                   "project_123",
				Code:                       "test_123",
				PendingAuthenticationToken: "cTDQJTTkTkkVYxQUlKBIxEsFs",
			},
			expected: AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.AuthenticateWithEmailVerificationCode(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func TestAuthenticateUserWithOrganizationSelection(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithOrganizationSelectionOpts
		expected AuthenticateResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns a User",
			client:   NewClient("test"),
			options: AuthenticateWithOrganizationSelectionOpts{
				ClientID:                   "project_123",
				OrganizationID:             "org_123",
				PendingAuthenticationToken: "cTDQJTTkTkkVYxQUlKBIxEsFs",
			},
			expected: AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.AuthenticateWithOrganizationSelection(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func authenticationResponseTestHandler(w http.ResponseWriter, r *http.Request) {
	payload := make(map[string]interface{})
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if secret, exists := payload["client_secret"].(string); exists && secret != "" {
		var response AuthenticateResponse

		switch secret {
		case "test":
			response = AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
				OrganizationID: "org_123",
			}
		case "test_with_impersonation":
			response = AuthenticateResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
				},
				OrganizationID: "org_123",
				AccessToken:    "access_token",
				RefreshToken:   "refresh_token",
				Impersonator: &Impersonator{
					Email:  "admin@example.com",
					Reason: "Helping debug a customer issue.",
				},
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
}

func refreshAuthenticationResponseTestHandler(w http.ResponseWriter, r *http.Request) {

	payload := make(map[string]interface{})
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if secret, exists := payload["client_secret"].(string); exists && secret != "" {
		response := AuthenticateResponse{
			AccessToken:  "access_token",
			RefreshToken: "new_refresh_token",
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
}

func TestGetEmailVerification(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetEmailVerificationOpts
		expected EmailVerification
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns EmailVerification by ID",
			client:   NewClient("test"),
			options:  GetEmailVerificationOpts{EmailVerification: "email_verification_123"},
			expected: EmailVerification{
				ID:        "email_verification_123",
				UserId:    "user_123",
				Email:     "marcelina@foo-corp.com",
				ExpiresAt: "2021-06-25T19:07:33.155Z",
				Code:      "123456",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getEmailVerificationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			emailVerification, err := client.GetEmailVerification(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, emailVerification)
		})
	}
}

func getEmailVerificationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/email_verification/email_verification_123" {
		emailVerification := EmailVerification{
			ID:        "email_verification_123",
			UserId:    "user_123",
			Email:     "marcelina@foo-corp.com",
			ExpiresAt: "2021-06-25T19:07:33.155Z",
			Code:      "123456",
			CreatedAt: "2021-06-25T19:07:33.155Z",
			UpdatedAt: "2021-06-25T19:07:33.155Z",
		}
		body, err = json.Marshal(emailVerification)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestSendVerificationEmail(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SendVerificationEmailOpts
		expected UserResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: SendVerificationEmailOpts{
				User: "user_123",
			},
			expected: UserResponse{
				User: User{
					ID:            "user_123",
					Email:         "marcelina@foo-corp.com",
					FirstName:     "Marcelina",
					LastName:      "Davis",
					EmailVerified: true,
					CreatedAt:     "2021-06-25T19:07:33.155Z",
					UpdatedAt:     "2021-06-25T19:07:33.155Z",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(sendVerificationEmailTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.SendVerificationEmail(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func sendVerificationEmailTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users/user_123/email_verification/send" {
		body, err = json.Marshal(UserResponse{
			User: User{
				ID: "user_123",

				Email:         "marcelina@foo-corp.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: true,
				CreatedAt:     "2021-06-25T19:07:33.155Z",
				UpdatedAt:     "2021-06-25T19:07:33.155Z",
			},
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestVerifyEmail(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifyEmailOpts
		expected UserResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: VerifyEmailOpts{
				User: "user_123",
				Code: "testToken",
			},
			expected: UserResponse{
				User: User{
					ID:            "user_123",
					Email:         "marcelina@foo-corp.com",
					FirstName:     "Marcelina",
					LastName:      "Davis",
					EmailVerified: true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(verifyEmailCodeTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.VerifyEmail(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func verifyEmailCodeTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users/user_123/email_verification/confirm" {
		body, err = json.Marshal(UserResponse{
			User: User{
				ID:            "user_123",
				Email:         "marcelina@foo-corp.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: true,
			},
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestGetPasswordReset(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetPasswordResetOpts
		expected PasswordReset
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns PasswordReset by ID",
			client:   NewClient("test"),
			options:  GetPasswordResetOpts{PasswordReset: "password_reset_123"},
			expected: PasswordReset{
				ID:                 "password_reset_123",
				UserId:             "user_123",
				Email:              "marcelina@foo-corp.com",
				PasswordResetToken: "myToken",
				PasswordResetUrl:   "https://your-app.com/reset-password?token=myToken",
				ExpiresAt:          "2021-06-25T19:07:33.155Z",
				CreatedAt:          "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getPasswordResetTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			passwordReset, err := client.GetPasswordReset(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, passwordReset)
		})
	}
}

func getPasswordResetTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/password_reset/password_reset_123" {
		passwordReset := PasswordReset{
			ID:                 "password_reset_123",
			UserId:             "user_123",
			Email:              "marcelina@foo-corp.com",
			PasswordResetToken: "myToken",
			PasswordResetUrl:   "https://your-app.com/reset-password?token=myToken",
			ExpiresAt:          "2021-06-25T19:07:33.155Z",
			CreatedAt:          "2021-06-25T19:07:33.155Z",
		}
		body, err = json.Marshal(passwordReset)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreatePasswordReset(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreatePasswordResetOpts
		expected PasswordReset
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns Password Reset",
			client:   NewClient("test"),
			options: CreatePasswordResetOpts{
				Email: "marcelina@foo-corp.com",
			},
			expected: PasswordReset{
				ID:                 "password_reset_123",
				UserId:             "user_123",
				Email:              "marcelina@foo-corp.com",
				PasswordResetToken: "myToken",
				PasswordResetUrl:   "https://your-app.com/reset-password?token=myToken",
				ExpiresAt:          "2021-06-25T19:07:33.155Z",
				CreatedAt:          "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(CreatePasswordResetTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			passwordReset, err := client.CreatePasswordReset(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, passwordReset)
		})
	}
}

func CreatePasswordResetTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/password_reset" {
		body, err = json.Marshal(
			PasswordReset{
				ID:                 "password_reset_123",
				UserId:             "user_123",
				Email:              "marcelina@foo-corp.com",
				PasswordResetToken: "myToken",
				PasswordResetUrl:   "https://your-app.com/reset-password?token=myToken",
				ExpiresAt:          "2021-06-25T19:07:33.155Z",
				CreatedAt:          "2021-06-25T19:07:33.155Z",
			})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestSendPasswordResetEmail(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SendPasswordResetEmailOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Successful request",
			client:   NewClient("test"),
			options: SendPasswordResetEmailOpts{
				Email:            "marcelina@foo-corp.com",
				PasswordResetUrl: "https://foo-corp.com/reset-password",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(sendPasswordResetEmailTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.SendPasswordResetEmail(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func sendPasswordResetEmailTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func TestResetPassword(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ResetPasswordOpts
		expected UserResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: ResetPasswordOpts{
				Token: "testToken",
			},
			expected: UserResponse{
				User: User{
					ID: "user_123",

					Email:         "marcelina@foo-corp.com",
					FirstName:     "Marcelina",
					LastName:      "Davis",
					EmailVerified: true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(resetPasswordHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.ResetPassword(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/password_reset/confirm" {
		body, err = json.Marshal(UserResponse{
			User: User{
				ID: "user_123",

				Email:         "marcelina@foo-corp.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: true,
			},
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestGetMagicAuth(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetMagicAuthOpts
		expected MagicAuth
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns MagicAuth by ID",
			client:   NewClient("test"),
			options:  GetMagicAuthOpts{MagicAuth: "magic_auth_123"},
			expected: MagicAuth{
				ID:        "magic_auth_123",
				UserId:    "user_123",
				Email:     "marcelina@foo-corp.com",
				ExpiresAt: "2021-06-25T19:07:33.155Z",
				Code:      "123456",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getMagicAuthTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			magicAuth, err := client.GetMagicAuth(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, magicAuth)
		})
	}
}

func getMagicAuthTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/magic_auth/magic_auth_123" {
		magicAuth := MagicAuth{
			ID:        "magic_auth_123",
			UserId:    "user_123",
			Email:     "marcelina@foo-corp.com",
			ExpiresAt: "2021-06-25T19:07:33.155Z",
			Code:      "123456",
			CreatedAt: "2021-06-25T19:07:33.155Z",
			UpdatedAt: "2021-06-25T19:07:33.155Z",
		}
		body, err = json.Marshal(magicAuth)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateMagicAuth(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateMagicAuthOpts
		expected MagicAuth
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns MagicAuth",
			client:   NewClient("test"),
			options: CreateMagicAuthOpts{
				Email: "marcelina@foo-corp.com",
			},
			expected: MagicAuth{
				ID:        "magic_auth_123",
				UserId:    "user_123",
				Email:     "marcelina@foo-corp.com",
				ExpiresAt: "2021-06-25T19:07:33.155Z",
				Code:      "123456",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(CreateMagicAuthTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			magicAuth, err := client.CreateMagicAuth(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, magicAuth)
		})
	}
}

func CreateMagicAuthTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/magic_auth" {
		body, err = json.Marshal(
			MagicAuth{
				ID:        "magic_auth_123",
				UserId:    "user_123",
				Email:     "marcelina@foo-corp.com",
				ExpiresAt: "2021-06-25T19:07:33.155Z",
				Code:      "123456",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestSendMagicAuthCode(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SendMagicAuthCodeOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Successful request",
			client:   NewClient("test"),
			options: SendMagicAuthCodeOpts{
				Email: "marcelina@foo-corp.com",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(sendMagicAuthCodeTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.SendMagicAuthCode(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func sendMagicAuthCodeTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func TestEnrollAuthFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  EnrollAuthFactorOpts
		expected EnrollAuthFactorResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: EnrollAuthFactorOpts{
				User: "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				Type: mfa.TOTP,
			},
			expected: EnrollAuthFactorResponse{
				Factor: mfa.Factor{
					ID:        "auth_factor_test123",
					CreatedAt: "2022-02-17T22:39:26.616Z",
					UpdatedAt: "2022-02-17T22:39:26.616Z",
					Type:      "generic_otp",
				},
				Challenge: mfa.Challenge{
					ID:        "auth_challenge_test123",
					CreatedAt: "2022-02-17T22:39:26.616Z",
					UpdatedAt: "2022-02-17T22:39:26.616Z",
					FactorID:  "auth_factor_test123",
					ExpiresAt: "2022-02-17T22:39:26.616Z",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(enrollAuthFactorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.EnrollAuthFactor(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func enrollAuthFactorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH/auth_factors" {
		body, err = json.Marshal(EnrollAuthFactorResponse{
			Factor: mfa.Factor{
				ID:        "auth_factor_test123",
				CreatedAt: "2022-02-17T22:39:26.616Z",
				UpdatedAt: "2022-02-17T22:39:26.616Z",
				Type:      "generic_otp",
			},
			Challenge: mfa.Challenge{
				ID:        "auth_challenge_test123",
				CreatedAt: "2022-02-17T22:39:26.616Z",
				UpdatedAt: "2022-02-17T22:39:26.616Z",
				FactorID:  "auth_factor_test123",
				ExpiresAt: "2022-02-17T22:39:26.616Z",
			},
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListAuthFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListAuthFactorsOpts
		expected ListAuthFactorsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns User",
			client:   NewClient("test"),
			options: ListAuthFactorsOpts{
				User: "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			},
			expected: ListAuthFactorsResponse{
				Data: []mfa.Factor{
					{
						ID:        "auth_factor_test123",
						CreatedAt: "2022-02-17T22:39:26.616Z",
						UpdatedAt: "2022-02-17T22:39:26.616Z",
						Type:      "generic_otp",
					},
					{
						ID:        "auth_factor_test234",
						CreatedAt: "2022-02-17T22:39:26.616Z",
						UpdatedAt: "2022-02-17T22:39:26.616Z",
						Type:      "generic_otp",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listAuthFactorsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.ListAuthFactors(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func listAuthFactorsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH/auth_factors" {
		body, err = json.Marshal(ListAuthFactorsResponse{
			Data: []mfa.Factor{
				{
					ID:        "auth_factor_test123",
					CreatedAt: "2022-02-17T22:39:26.616Z",
					UpdatedAt: "2022-02-17T22:39:26.616Z",
					Type:      "generic_otp",
				},
				{
					ID:        "auth_factor_test234",
					CreatedAt: "2022-02-17T22:39:26.616Z",
					UpdatedAt: "2022-02-17T22:39:26.616Z",
					Type:      "generic_otp",
				},
			},
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestGetOrganizationMembership(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetOrganizationMembershipOpts
		expected OrganizationMembership
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns an Organization Membership",
			client:   NewClient("test"),
			options: GetOrganizationMembershipOpts{
				OrganizationMembership: "om_01E4ZCR3C56J083X43JQXF3JK5",
			},
			expected: OrganizationMembership{
				ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
				UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
				OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
				Status:         Active,
				CreatedAt:      "2021-06-25T19:07:33.155Z",
				UpdatedAt:      "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getOrganizationMembershipTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organizationMembership, err := client.GetOrganizationMembership(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organizationMembership)
		})
	}
}

func getOrganizationMembershipTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5" {
		body, err = json.Marshal(OrganizationMembership{
			ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
			UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
			OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
			Status:         Active,
			CreatedAt:      "2021-06-25T19:07:33.155Z",
			UpdatedAt:      "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListOrganizationMemberships(t *testing.T) {
	t.Run("ListOrganizationMemberships succeeds to fetch OrganizationMemberships belonging to an Organization", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(listOrganizationMembershipsTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		expectedResponse := ListOrganizationMembershipsResponse{
			Data: []OrganizationMembership{
				{
					ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
					UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
					OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
					Status:         Active,
					CreatedAt:      "2021-06-25T19:07:33.155Z",
					UpdatedAt:      "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		}

		organizationMemberships, err := client.ListOrganizationMemberships(
			context.Background(),
			ListOrganizationMembershipsOpts{OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5"},
		)

		require.NoError(t, err)
		require.Equal(t, expectedResponse, organizationMemberships)
	})

	t.Run("ListOrganizationMemberships succeeds to fetch OrganizationMemberships belonging to a User", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(listOrganizationMembershipsTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		expectedResponse := ListOrganizationMembershipsResponse{
			Data: []OrganizationMembership{
				{
					ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
					UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
					OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
					Status:         Active,
					CreatedAt:      "2021-06-25T19:07:33.155Z",
					UpdatedAt:      "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		}

		organizationMemberships, err := client.ListOrganizationMemberships(
			context.Background(),
			ListOrganizationMembershipsOpts{UserID: "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E"},
		)

		require.NoError(t, err)
		require.Equal(t, expectedResponse, organizationMemberships)
	})

	t.Run("ListOrganizationMemberships succeeds to fetch OrganizationMemberships belonging to a User with particular statuses", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(listOrganizationMembershipsTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		expectedResponse := ListOrganizationMembershipsResponse{
			Data: []OrganizationMembership{
				{
					ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
					UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
					OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
					Status:         Active,
					CreatedAt:      "2021-06-25T19:07:33.155Z",
					UpdatedAt:      "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		}

		organizationMemberships, err := client.ListOrganizationMemberships(
			context.Background(),
			ListOrganizationMembershipsOpts{Statuses: []OrganizationMembershipStatus{Active, Inactive}, UserID: "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E"},
		)

		require.NoError(t, err)
		require.Equal(t, expectedResponse, organizationMemberships)
	})
}

func listOrganizationMembershipsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/organization_memberships" {
		body, err = json.Marshal(struct {
			ListOrganizationMembershipsResponse
		}{
			ListOrganizationMembershipsResponse: ListOrganizationMembershipsResponse{
				Data: []OrganizationMembership{
					{
						ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
						UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
						OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
						Status:         Active,
						CreatedAt:      "2021-06-25T19:07:33.155Z",
						UpdatedAt:      "2021-06-25T19:07:33.155Z",
					},
				},
				ListMetadata: common.ListMetadata{
					After: "",
				},
			},
		})
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateOrganizationMembership(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateOrganizationMembershipOpts
		expected OrganizationMembership
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns OrganizationMembership",
			client:   NewClient("test"),
			options: CreateOrganizationMembershipOpts{
				UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
				OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
			},
			expected: OrganizationMembership{
				ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
				UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
				OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
				Status:         Active,
				Role: common.RoleResponse{
					Slug: "member",
				},
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createOrganizationMembershipTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.CreateOrganizationMembership(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func createOrganizationMembershipTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/organization_memberships" {
		body, err = json.Marshal(OrganizationMembership{
			ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
			UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
			OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
			Status:         Active,
			Role: common.RoleResponse{
				Slug: "member",
			},
			CreatedAt: "2021-06-25T19:07:33.155Z",
			UpdatedAt: "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestUpdateOrganizationMembership(t *testing.T) {
	tests := []struct {
		scenario                 string
		client                   *Client
		organizationMembershipId string
		options                  UpdateOrganizationMembershipOpts
		expected                 OrganizationMembership
		err                      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario:                 "Request returns OrganizationMembership",
			client:                   NewClient("test"),
			organizationMembershipId: "om_01E4ZCR3C56J083X43JQXF3JK5",
			options: UpdateOrganizationMembershipOpts{
				RoleSlug: "member",
			},
			expected: OrganizationMembership{
				ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
				UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
				OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
				Status:         Active,
				Role: common.RoleResponse{
					Slug: "member",
				},
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateOrganizationMembershipTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			body, err := client.UpdateOrganizationMembership(context.Background(), test.organizationMembershipId, test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, body)
		})
	}
}

func updateOrganizationMembershipTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5" {
		body, err = json.Marshal(OrganizationMembership{
			ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
			UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
			OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
			Status:         Active,
			Role: common.RoleResponse{
				Slug: "member",
			},
			CreatedAt: "2021-06-25T19:07:33.155Z",
			UpdatedAt: "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestDeleteOrganizationMembership(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteOrganizationMembershipOpts
		expected error
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns OrganizationMembership",
			client:   NewClient("test"),
			options: DeleteOrganizationMembershipOpts{
				OrganizationMembership: "om_01E4ZCR3C56J083X43JQXF3JK5",
			},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteOrganizationMembershipTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.DeleteOrganizationMembership(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, err)
		})
	}
}

func deleteOrganizationMembershipTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5" {
		body, err = nil, nil
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestDeactivateOrganizationMembership(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeactivateOrganizationMembershipOpts
		expected OrganizationMembership
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns an Organization Membership",
			client:   NewClient("test"),
			options: DeactivateOrganizationMembershipOpts{
				OrganizationMembership: "om_01E4ZCR3C56J083X43JQXF3JK5",
			},
			expected: OrganizationMembership{
				ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
				UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
				OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
				Status:         Inactive,
				CreatedAt:      "2021-06-25T19:07:33.155Z",
				UpdatedAt:      "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deactivateOrganizationMembershipTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organizationMembership, err := client.DeactivateOrganizationMembership(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organizationMembership)
		})
	}
}

func deactivateOrganizationMembershipTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5/deactivate" {
		body, err = json.Marshal(OrganizationMembership{
			ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
			UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
			OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
			Status:         Inactive,
			CreatedAt:      "2021-06-25T19:07:33.155Z",
			UpdatedAt:      "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestReactivateOrganizationMembership(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ReactivateOrganizationMembershipOpts
		expected OrganizationMembership
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns an Organization Membership",
			client:   NewClient("test"),
			options: ReactivateOrganizationMembershipOpts{
				OrganizationMembership: "om_01E4ZCR3C56J083X43JQXF3JK5",
			},
			expected: OrganizationMembership{
				ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
				UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
				OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
				Status:         Active,
				CreatedAt:      "2021-06-25T19:07:33.155Z",
				UpdatedAt:      "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(reactivateOrganizationMembershipTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organizationMembership, err := client.ReactivateOrganizationMembership(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organizationMembership)
		})
	}
}

func reactivateOrganizationMembershipTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5/reactivate" {
		body, err = json.Marshal(OrganizationMembership{
			ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
			UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
			OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
			Status:         Active,
			CreatedAt:      "2021-06-25T19:07:33.155Z",
			UpdatedAt:      "2021-06-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestGetInvitation(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetInvitationOpts
		expected Invitation
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns Invitation by ID",
			client:   NewClient("test"),
			options:  GetInvitationOpts{Invitation: "invitation_123"},
			expected: Invitation{
				ID:                  "invitation_123",
				Email:               "marcelina@foo-corp.com",
				State:               Pending,
				Token:               "myToken",
				AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
				ExpiresAt:           "2021-06-25T19:07:33.155Z",
				CreatedAt:           "2021-06-25T19:07:33.155Z",
				UpdatedAt:           "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getInvitationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			invitation, err := client.GetInvitation(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, invitation)
		})
	}
}

func getInvitationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/invitations/invitation_123" {
		invitations := Invitation{
			ID:                  "invitation_123",
			Email:               "marcelina@foo-corp.com",
			State:               Pending,
			Token:               "myToken",
			AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
			ExpiresAt:           "2021-06-25T19:07:33.155Z",
			CreatedAt:           "2021-06-25T19:07:33.155Z",
			UpdatedAt:           "2021-06-25T19:07:33.155Z",
		}
		body, err = json.Marshal(invitations)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestFindInvitationByToken(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  FindInvitationByTokenOpts
		expected Invitation
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns Invitation by token",
			client:   NewClient("test"),
			options:  FindInvitationByTokenOpts{InvitationToken: "myToken"},
			expected: Invitation{
				ID:                  "invitation_123",
				Email:               "marcelina@foo-corp.com",
				State:               Pending,
				Token:               "myToken",
				AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
				ExpiresAt:           "2021-06-25T19:07:33.155Z",
				CreatedAt:           "2021-06-25T19:07:33.155Z",
				UpdatedAt:           "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(findInvitationByTokenTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			invitation, err := client.FindInvitationByToken(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, invitation)
		})
	}
}

func findInvitationByTokenTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/invitations/by_token/myToken" {
		invitation := Invitation{
			ID:                  "invitation_123",
			Email:               "marcelina@foo-corp.com",
			State:               Pending,
			Token:               "myToken",
			AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
			ExpiresAt:           "2021-06-25T19:07:33.155Z",
			CreatedAt:           "2021-06-25T19:07:33.155Z",
			UpdatedAt:           "2021-06-25T19:07:33.155Z",
		}
		body, err = json.Marshal(invitation)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListInvitations(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListInvitationsOpts
		expected ListInvitationsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns list of invitations",
			client:   NewClient("test"),
			options: ListInvitationsOpts{
				Email: "marcelina@foo-corp.com",
			},
			expected: ListInvitationsResponse{
				Data: []Invitation{
					{
						ID:                  "invitation_123",
						Email:               "marcelina@foo-corp.com",
						State:               Pending,
						Token:               "myToken",
						AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
						ExpiresAt:           "2021-06-25T19:07:33.155Z",
						CreatedAt:           "2021-06-25T19:07:33.155Z",
						UpdatedAt:           "2021-06-25T19:07:33.155Z",
					},
				},
				ListMetadata: common.ListMetadata{
					After: "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listInvitationsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			invitations, err := client.ListInvitations(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, invitations)
		})
	}
}

func listInvitationsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/invitations" {
		invitations := ListInvitationsResponse{
			Data: []Invitation{
				{
					ID:                  "invitation_123",
					Email:               "marcelina@foo-corp.com",
					State:               Pending,
					Token:               "myToken",
					AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
					ExpiresAt:           "2021-06-25T19:07:33.155Z",
					CreatedAt:           "2021-06-25T19:07:33.155Z",
					UpdatedAt:           "2021-06-25T19:07:33.155Z",
				},
			},
			ListMetadata: common.ListMetadata{
				After: "",
			},
		}
		body, err = json.Marshal(invitations)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestSendInvitation(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SendInvitationOpts
		expected Invitation
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns Invitation",
			client:   NewClient("test"),
			options: SendInvitationOpts{
				Email:          "marcelina@foo-corp.com",
				OrganizationID: "org_123",
				ExpiresInDays:  7,
				InviterUserID:  "user_123",
				RoleSlug:       "admin",
			},
			expected: Invitation{
				ID:                  "invitation_123",
				Email:               "marcelina@foo-corp.com",
				State:               Pending,
				Token:               "myToken",
				AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
				ExpiresAt:           "2021-06-25T19:07:33.155Z",
				CreatedAt:           "2021-06-25T19:07:33.155Z",
				UpdatedAt:           "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(SendInvitationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			Invitation, err := client.SendInvitation(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, Invitation)
		})
	}
}

func SendInvitationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/invitations" {
		body, err = json.Marshal(
			Invitation{
				ID:                  "invitation_123",
				Email:               "marcelina@foo-corp.com",
				State:               Pending,
				Token:               "myToken",
				AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
				ExpiresAt:           "2021-06-25T19:07:33.155Z",
				CreatedAt:           "2021-06-25T19:07:33.155Z",
				UpdatedAt:           "2021-06-25T19:07:33.155Z",
			})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestRevokeInvitation(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  RevokeInvitationOpts
		expected Invitation
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns Invitation",
			client:   NewClient("test"),
			options: RevokeInvitationOpts{
				Invitation: "invitation_123",
			},
			expected: Invitation{

				ID:                  "invitation_123",
				Email:               "marcelina@foo-corp.com",
				State:               Pending,
				Token:               "myToken",
				AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
				ExpiresAt:           "2021-06-25T19:07:33.155Z",
				CreatedAt:           "2021-06-25T19:07:33.155Z",
				UpdatedAt:           "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(RevokeInvitationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			Invitation, err := client.RevokeInvitation(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, Invitation)
		})
	}
}

func TestGetLogoutURL(t *testing.T) {
	tests := []struct {
		scenario string
		options  GetLogoutURLOpts
		expected string
		err      bool
	}{
		{
			scenario: "Returns the logout URL",
			options: GetLogoutURLOpts{
				SessionID: "session_123",
			},
			expected: "https://api.workos.com/user_management/sessions/logout?session_id=session_123",
		},
		{
			scenario: "Returns an error if no SessionID is given",
			options:  GetLogoutURLOpts{},
			err:      true,
		},
		{
			scenario: "Includes return_to if given",
			options: GetLogoutURLOpts{
				SessionID: "session_123",
				ReturnTo:  "https://your-app.com",
			},
			expected: "https://api.workos.com/user_management/sessions/logout?return_to=https%3A%2F%2Fyour-app.com&session_id=session_123",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client := NewClient("test")

			url, err := client.GetLogoutURL(test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, url.String())
		})
	}
}

func RevokeInvitationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/user_management/invitations/invitation_123/revoke" {
		body, err = json.Marshal(
			Invitation{
				ID:                  "invitation_123",
				Email:               "marcelina@foo-corp.com",
				State:               Pending,
				Token:               "myToken",
				AcceptInvitationUrl: "https://your-app.com/invite?invitation_token=myToken",
				ExpiresAt:           "2021-06-25T19:07:33.155Z",
				CreatedAt:           "2021-06-25T19:07:33.155Z",
				UpdatedAt:           "2021-06-25T19:07:33.155Z",
			})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func RevokeSessionTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
