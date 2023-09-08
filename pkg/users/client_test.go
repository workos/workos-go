package users

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v2/pkg/common"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

	if r.URL.Path == "/users/user_123" {
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

	if r.URL.Path == "/users" {
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

	if r.URL.Path == "/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH" {
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

func TestUpdateUserPassword(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdateUserPasswordOpts
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
			options: UpdateUserPasswordOpts{
				User:     "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				Password: "pass_123",
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
			server := httptest.NewServer(http.HandlerFunc(updateUserPasswordTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.UpdateUserPassword(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func updateUserPasswordTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH/password" {
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

	if r.URL.Path == "/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH" {
		body, err = nil, nil
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestAddUserToOrganization(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AddUserToOrganizationOpts
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
			options: AddUserToOrganizationOpts{
				User:         "user_managed_id",
				Organization: "foo_corp_id",
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
			server := httptest.NewServer(http.HandlerFunc(addUserToOrganizationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.AddUserToOrganization(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func addUserToOrganizationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/user_managed_id/organizations" {
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

func TestRemoveUserFromOrganization(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  RemoveUserFromOrganizationOpts
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
			options: RemoveUserFromOrganizationOpts{
				User:         "user_managed_id",
				Organization: "foo_corp_id",
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
			server := httptest.NewServer(http.HandlerFunc(removeUserFromOrganizationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.RemoveUserFromOrganization(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func removeUserFromOrganizationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/user_managed_id/organizations/foo_corp_id" {
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

func TestAuthenticateUserWithPassword(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithPasswordOpts
		expected AuthenticationResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns an AuthenticationResponse",
			client:   NewClient("test"),
			options: AuthenticateWithPasswordOpts{
				ClientID: "project_123",
				Email:    "employee@foo-corp.com",
				Password: "test_123",
			},
			expected: AuthenticationResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
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

			authenticationresponse, err := client.AuthenticateWithPassword(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, authenticationresponse)
		})
	}
}

func TestAuthenticateUserWithCode(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithCodeOpts
		expected AuthenticationResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns an AuthenticationResponse",
			client:   NewClient("test"),
			options: AuthenticateWithCodeOpts{
				ClientID: "project_123",
				Code:     "test_123",
			},
			expected: AuthenticationResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
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

			authenticationresponse, err := client.AuthenticateWithCode(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, authenticationresponse)
		})
	}
}

func TestAuthenticateUserWithMagicAuth(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithMagicAuthOpts
		expected AuthenticationResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns an AuthenticationResponse",
			client:   NewClient("test"),
			options: AuthenticateWithMagicAuthOpts{
				ClientID: "project_123",
				Code:     "test_123",
				User:     "user_123",
			},
			expected: AuthenticationResponse{
				User: User{
					ID:        "testUserID",
					FirstName: "John",
					LastName:  "Doe",
					Email:     "employee@foo-corp.com",
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

			authenticationresponse, err := client.AuthenticateWithMagicAuth(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, authenticationresponse)
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
		response := AuthenticationResponse{
			User: User{
				ID:        "testUserID",
				FirstName: "John",
				LastName:  "Doe",
				Email:     "employee@foo-corp.com",
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
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

	if r.URL.Path == "/users/user_123/send_verification_email" {
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

func TestVerifyEmailCode(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifyEmailCodeOpts
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
			options: VerifyEmailCodeOpts{
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

			user, err := client.VerifyEmailCode(context.Background(), test.options)
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

	if r.URL.Path == "/users/user_123/verify_email_code" {
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

func TestCreatePasswordResetChallenge(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreatePasswordResetChallengeOpts
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
			options: CreatePasswordResetChallengeOpts{
				Email:            "marcelina@foo-corp.com",
				PasswordResetUrl: "https://foo-corp.com/reset-password",
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
			server := httptest.NewServer(http.HandlerFunc(createPasswordResetChallengeHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.CreatePasswordResetChallenge(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func createPasswordResetChallengeHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/password_reset_challenge" {
		body, err = json.Marshal(UserResponse{
			User: User{
				ID:            "user_123",
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

func TestCompletePasswordReset(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CompletePasswordResetOpts
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
			options: CompletePasswordResetOpts{
				Token: "testToken",
			},
			expected: User{
				ID: "user_123",

				Email:         "marcelina@foo-corp.com",
				FirstName:     "Marcelina",
				LastName:      "Davis",
				EmailVerified: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(completePasswordResetHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.CompletePasswordReset(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func completePasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/password_reset" {
		body, err = json.Marshal(User{
			ID:            "user_123",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
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
			options: SendMagicAuthCodeOpts{
				Email: "marcelina@foo-corp.com",
			},
			expected: User{
				ID:        "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				Email:     "marcelina@foo-corp.com",
				FirstName: "Marcelina",
				LastName:  "Davis",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
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

			user, err := client.SendMagicAuthCode(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func sendMagicAuthCodeTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/magic_auth/send" {
		body, err = json.Marshal(User{
			ID:        "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			Email:     "marcelina@foo-corp.com",
			FirstName: "Marcelina",
			LastName:  "Davis",
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
