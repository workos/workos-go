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
			scenario: "Request returns a managed User",
			client:   NewClient("test"),
			options: GetUserOpts{
				User: "user_managed_id",
			},
			expected: User{
				ID:           "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				UserType:     Managed,
				Email:        "marcelina@foo-corp.com",
				FirstName:    "Marcelina",
				LastName:     "Davis",
				SSOProfileID: "prof_01E55M8ZA10HV0XERJYW0PM277",
				CreatedAt:    "2021-06-25T19:07:33.155Z",
				UpdatedAt:    "2021-06-25T19:07:33.155Z",
			},
		},
		{
			scenario: "Request returns an unmanaged User",
			client:   NewClient("test"),
			options: GetUserOpts{
				User: "user_unmanaged_id",
			},
			expected: User{
				ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
				CreatedAt:       "2021-06-25T19:07:33.155Z",
				UpdatedAt:       "2021-06-25T19:07:33.155Z",
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

	if r.URL.Path == "/users/user_managed_id" {
		body, err = json.Marshal(User{
			ID:           "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			UserType:     Managed,
			Email:        "marcelina@foo-corp.com",
			FirstName:    "Marcelina",
			LastName:     "Davis",
			SSOProfileID: "prof_01E55M8ZA10HV0XERJYW0PM277",
			CreatedAt:    "2021-06-25T19:07:33.155Z",
			UpdatedAt:    "2021-06-25T19:07:33.155Z",
		})
	} else if r.URL.Path == "/users/user_unmanaged_id" {
		body, err = json.Marshal(User{
			ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			UserType:        Unmanaged,
			Email:           "marcelina@foo-corp.com",
			FirstName:       "Marcelina",
			LastName:        "Davis",
			EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
			CreatedAt:       "2021-06-25T19:07:33.155Z",
			UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
					ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					UserType:        Unmanaged,
					Email:           "marcelina@foo-corp.com",
					FirstName:       "Marcelina",
					LastName:        "Davis",
					EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
					CreatedAt:       "2021-06-25T19:07:33.155Z",
					UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
					ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					UserType:        Unmanaged,
					Email:           "marcelina@foo-corp.com",
					FirstName:       "Marcelina",
					LastName:        "Davis",
					EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
					CreatedAt:       "2021-06-25T19:07:33.155Z",
					UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
					ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
					UserType:        Unmanaged,
					Email:           "marcelina@foo-corp.com",
					FirstName:       "Marcelina",
					LastName:        "Davis",
					EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
					CreatedAt:       "2021-06-25T19:07:33.155Z",
					UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
				ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
				CreatedAt:       "2021-06-25T19:07:33.155Z",
				UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
			ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			UserType:        Unmanaged,
			Email:           "marcelina@foo-corp.com",
			FirstName:       "Marcelina",
			LastName:        "Davis",
			EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
			CreatedAt:       "2021-06-25T19:07:33.155Z",
			UpdatedAt:       "2021-06-25T19:07:33.155Z",
		})
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
				ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
				CreatedAt:       "2021-06-25T19:07:33.155Z",
				UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
			ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			UserType:        Unmanaged,
			Email:           "marcelina@foo-corp.com",
			FirstName:       "Marcelina",
			LastName:        "Davis",
			EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
			CreatedAt:       "2021-06-25T19:07:33.155Z",
			UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
				ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
				CreatedAt:       "2021-06-25T19:07:33.155Z",
				UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
			ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			UserType:        Unmanaged,
			Email:           "marcelina@foo-corp.com",
			FirstName:       "Marcelina",
			LastName:        "Davis",
			EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
			CreatedAt:       "2021-06-25T19:07:33.155Z",
			UpdatedAt:       "2021-06-25T19:07:33.155Z",
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
		options  AuthenticateUserWithPasswordOpts
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
			options: AuthenticateUserWithPasswordOpts{
				Email:    "employee@foo-corp.com",
				Password: "test_123",
			},
			expected: AuthenticationResponse{
				Session: Session{
					ID:        "testSessionID",
					Token:     "testSessionToken",
					CreatedAt: "2023-08-05T14:48:00.000Z",
					ExpiresAt: "2023-08-05T14:50:00.000Z",
				},
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
			server := httptest.NewServer(http.HandlerFunc(getAuthenticationResponseHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			authenticationresponse, err := client.AuthenticateUserWithPassword(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, authenticationresponse)
		})
	}
}

func getAuthenticationResponseHandler(w http.ResponseWriter, r *http.Request) {

	payload := make(map[string]interface{})
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if secret, exists := payload["client_secret"].(string); exists && secret != "" {
		response := AuthenticationResponse{
			Session: Session{
				ID:        "testSessionID",
				Token:     "testSessionToken",
				CreatedAt: "2023-08-05T14:48:00.000Z",
				ExpiresAt: "2023-08-05T14:50:00.000Z",
			},
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

func TestAuthenticateUserWithToken(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthenticateUserWithTokenOpts
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
			options: AuthenticateUserWithTokenOpts{
				ClientID: "project_123",
				Code:     "test_123",
			},
			expected: AuthenticationResponse{
				Session: Session{
					ID:        "testSessionID",
					Token:     "testSessionToken",
					CreatedAt: "2023-08-05T14:48:00.000Z",
					ExpiresAt: "2023-08-05T14:50:00.000Z",
				},
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
			server := httptest.NewServer(http.HandlerFunc(getAuthenticationResponseHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			authenticationresponse, err := client.AuthenticateUserWithToken(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, authenticationresponse)
		})
	}
}

func TestCreateEmailVerificationChallenge(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateEmailVerificationChallengeOpts
		expected CreateEmailVerificationChallengeResponse
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
			options: CreateEmailVerificationChallengeOpts{
				User:            "user_unmanaged_id",
				VerificationUrl: "https://your-app.com/verify-email",
			},
			expected: CreateEmailVerificationChallengeResponse{
				User: User{
					ID:              "user_unmanaged_id",
					UserType:        Unmanaged,
					Email:           "marcelina@foo-corp.com",
					FirstName:       "Marcelina",
					LastName:        "Davis",
					EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
					CreatedAt:       "2021-06-25T19:07:33.155Z",
					UpdatedAt:       "2021-06-25T19:07:33.155Z",
				},
				Token: "testToken",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createEmailVerificationChallengeHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.CreateEmailVerificationChallenge(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func createEmailVerificationChallengeHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/user_unmanaged_id/email_verification_challenge" {
		body, err = json.Marshal(CreateEmailVerificationChallengeResponse{
			User: User{
				ID:              "user_unmanaged_id",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
				CreatedAt:       "2021-06-25T19:07:33.155Z",
				UpdatedAt:       "2021-06-25T19:07:33.155Z",
			}, Token: "testToken",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCompleteEmailVerification(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CompleteEmailVerificationOpts
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
			options: CompleteEmailVerificationOpts{
				Token: "testToken",
			},
			expected: User{
				ID:              "user_unmanaged_id",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(completeEmailVerificationHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			user, err := client.CompleteEmailVerification(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, user)
		})
	}
}

func completeEmailVerificationHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var body []byte
	var err error

	if r.URL.Path == "/users/email_verification" {
		body, err = json.Marshal(User{
			ID:              "user_unmanaged_id",
			UserType:        Unmanaged,
			Email:           "marcelina@foo-corp.com",
			FirstName:       "Marcelina",
			LastName:        "Davis",
			EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
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
		expected CreatePasswordResetChallengeResponse
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
			expected: CreatePasswordResetChallengeResponse{
				User: User{
					ID:              "user_unmanaged_id",
					UserType:        Unmanaged,
					Email:           "marcelina@foo-corp.com",
					FirstName:       "Marcelina",
					LastName:        "Davis",
					EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
					CreatedAt:       "2021-06-25T19:07:33.155Z",
					UpdatedAt:       "2021-06-25T19:07:33.155Z",
				},
				Token: "testToken",
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
		body, err = json.Marshal(CreatePasswordResetChallengeResponse{
			User: User{
				ID:              "user_unmanaged_id",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
				CreatedAt:       "2021-06-25T19:07:33.155Z",
				UpdatedAt:       "2021-06-25T19:07:33.155Z",
			}, Token: "testToken",
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
				ID:              "user_unmanaged_id",
				UserType:        Unmanaged,
				Email:           "marcelina@foo-corp.com",
				FirstName:       "Marcelina",
				LastName:        "Davis",
				EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
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
			ID:              "user_unmanaged_id",
			UserType:        Unmanaged,
			Email:           "marcelina@foo-corp.com",
			FirstName:       "Marcelina",
			LastName:        "Davis",
			EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestVerifySession(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifySessionOpts
		expected VerifySessionResponse
		err      bool
	}{
		{
			scenario: "Request returns a VerifySessionResponse",
			client:   NewClient("test"),
			options: VerifySessionOpts{
				Token:    "123",
				ClientID: "project_123",
			},
			expected: VerifySessionResponse{
				Session: Session{
					ID:        "testSessionID",
					Token:     "testSessionToken",
					CreatedAt: "2023-08-05T14:48:00.000Z",
					ExpiresAt: "2023-08-05T14:50:00.000Z",
				},
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
			server := httptest.NewServer(http.HandlerFunc(getVerifySessionHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			sessionresponse, err := client.VerifySession(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, sessionresponse)
		})
	}
}

func getVerifySessionHandler(w http.ResponseWriter, r *http.Request) {

	response := VerifySessionResponse{
		Session: Session{
			ID:        "testSessionID",
			Token:     "testSessionToken",
			CreatedAt: "2023-08-05T14:48:00.000Z",
			ExpiresAt: "2023-08-05T14:50:00.000Z",
		},
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

	w.WriteHeader(http.StatusUnauthorized)
}

func TestRevokeSession(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  RevokeSessionOpts
		expected bool
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns a boolean",
			client:   NewClient("test"),
			options: RevokeSessionOpts{
				SessionID:    "123",
				SessionToken: "345",
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getRevokeSessionHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.RevokeSession(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func TestRevokeAllSessionsForUser(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		userId   string
		expected bool
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   NewClient(""),
			err:      true,
		},
		{
			scenario: "Request returns a boolean",
			client:   NewClient("test"),
			userId:   "123",
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getRevokeSessionHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.RevokeAllSessionsForUser(context.Background(), test.userId)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func getRevokeSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "Bearer test" {
		response := true
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}
