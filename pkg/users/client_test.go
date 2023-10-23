package users

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v2/pkg/common"
	"github.com/workos/workos-go/v2/pkg/mfa"
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
		expected UserResponse
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
			expected: UserResponse{
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
		expected UserResponse
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
			expected: UserResponse{
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

func TestAuthenticateUserWithMagicAuth(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateWithMagicAuthOpts
		expected UserResponse
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
			expected: UserResponse{
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
		expected UserResponse
		err      bool
	}{{
		scenario: "Request without API Key returns an error",
		client:   NewClient(""),
		err:      true,
	},
		{
			scenario: "Request returns an AuthenticationResponse",
			client:   NewClient("test"),
			options: AuthenticateWithTOTPOpts{
				ClientID:                   "project_123",
				Code:                       "test_123",
				PendingAuthenticationToken: "cTDQJTTkTkkVYxQUlKBIxEsFs",
				AuthenticationChallengeID:  "auth_challenge_01H96FETXGTW1QMBSBT2T36PW0",
			},
			expected: UserResponse{
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

func authenticationResponseTestHandler(w http.ResponseWriter, r *http.Request) {

	payload := make(map[string]interface{})
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if secret, exists := payload["client_secret"].(string); exists && secret != "" {
		response := UserResponse{
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

func TestSendPasswordResetEmail(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SendPasswordResetEmailOpts
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
			options: SendPasswordResetEmailOpts{
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
			server := httptest.NewServer(http.HandlerFunc(sendPasswordResetEmailTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.SendPasswordResetEmail(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func sendPasswordResetEmailTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/send_password_reset_email" {
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

	if r.URL.Path == "/users/reset_password" {
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

func TestSendMagicAuthCode(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SendMagicAuthCodeOpts
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
			options: SendMagicAuthCodeOpts{
				Email: "marcelina@foo-corp.com",
			},
			expected: UserResponse{
				User: User{
					ID:        "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					Email:     "marcelina@foo-corp.com",
					FirstName: "Marcelina",
					LastName:  "Davis",
					CreatedAt: "2021-06-25T19:07:33.155Z",
					UpdatedAt: "2021-06-25T19:07:33.155Z",
				},
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
		body, err = json.Marshal(UserResponse{
			User: User{
				ID:        "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				Email:     "marcelina@foo-corp.com",
				FirstName: "Marcelina",
				LastName:  "Davis",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
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

func TestEnrollAuthFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  EnrollAuthFactorOpts
		expected AuthenticationResponse
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
			expected: AuthenticationResponse{
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

	if r.URL.Path == "/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH/auth/factors" {
		body, err = json.Marshal(AuthenticationResponse{
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

	if r.URL.Path == "/users/user_01E3JC5F5Z1YJNPGVYWV9SX6GH/auth/factors" {
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

func TestCreateInvitation(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateInvitationOpts
		expected InviteObject
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns InviteObject",
			client:   NewClient("test"),
			options: CreateInvitationOpts{
				Email:          "marcelina@foo-corp.com",
				OrganizationID: "org_123",
				ExpiresInDays:  7,
				InviterUserID:  "user_123",
			},
			expected: InviteObject{
				Object:    "invite",
				ID:        "invite_123",
				Email:     "marcelina@foo-corp.com",
				State:     "pending",
				Token:     "myToken",
				ExpiresAt: "2021-06-25T19:07:33.155Z",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createInvitationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			inviteObject, err := client.CreateInvitation(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, inviteObject)
		})
	}
}

func createInvitationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/invites" {
		body, err = json.Marshal(InviteObject{
			Object:    "invite",
			ID:        "invite_123",
			Email:     "marcelina@foo-corp.com",
			State:     "pending",
			Token:     "myToken",
			ExpiresAt: "2021-06-25T19:07:33.155Z",
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

func TestRevokeInvitation(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  RevokeInvitationOpts
		expected InviteObject
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns InviteObject",
			client:   NewClient("test"),
			options: RevokeInvitationOpts{
				InviteID: "invite_123",
			},
			expected: InviteObject{
				Object:    "invite",
				ID:        "invite_123",
				Email:     "marcelina@foo-corp.com",
				State:     "pending",
				Token:     "myToken",
				ExpiresAt: "2021-06-25T19:07:33.155Z",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(revokeInvitationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			inviteObject, err := client.RevokeInvitation(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, inviteObject)
		})
	}
}

func revokeInvitationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/invites/invite_123/revoke" {
		body, err = json.Marshal(InviteObject{
			Object:    "invite",
			ID:        "invite_123",
			Email:     "marcelina@foo-corp.com",
			State:     "pending",
			Token:     "myToken",
			ExpiresAt: "2021-06-25T19:07:33.155Z",
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

func TestListInvitations(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListInvitationsOpts
		expected []InviteObject
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns list of InviteObjects",
			client:   NewClient("test"),
			options: ListInvitationsOpts{
				Email: "marcelina@foo-corp.com",
			},
			expected: []InviteObject{
				{
					Object:    "invite",
					ID:        "invite_123",
					Email:     "marcelina@foo-corp.com",
					State:     "pending",
					Token:     "myToken",
					ExpiresAt: "2021-06-25T19:07:33.155Z",
					CreatedAt: "2021-06-25T19:07:33.155Z",
					UpdatedAt: "2021-06-25T19:07:33.155Z",
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

	if r.URL.Path == "/users/invites" {
		invites := []InviteObject{
			{
				Object:    "invite",
				ID:        "invite_123",
				Email:     "marcelina@foo-corp.com",
				State:     "pending",
				Token:     "myToken",
				ExpiresAt: "2021-06-25T19:07:33.155Z",
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		}
		body, err = json.Marshal(invites)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
