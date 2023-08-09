package users

import (
	"context"
	"github.com/workos/workos-go/v2/pkg/common"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func mockClient(s *httptest.Server) *Client {
	client := NewClient("")
	client.HTTPClient = s.Client()
	client.Endpoint = s.URL
	return client
}

func TestUsersGetUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getUserTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:           "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		UserType:     Managed,
		Email:        "marcelina@foo-corp.com",
		FirstName:    "Marcelina",
		LastName:     "Davis",
		SSOProfileID: "prof_01E55M8ZA10HV0XERJYW0PM277",
		CreatedAt:    "2021-06-25T19:07:33.155Z",
		UpdatedAt:    "2021-06-25T19:07:33.155Z",
	}

	userRes, err := GetUser(context.Background(), GetUserOpts{
		User: "user_managed_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersListUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listUsersTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

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

	userRes, err := ListUsers(context.Background(), ListUsersOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersCreateUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createUserTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		UserType:        Unmanaged,
		Email:           "marcelina@foo-corp.com",
		FirstName:       "Marcelina",
		LastName:        "Davis",
		EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
		CreatedAt:       "2021-06-25T19:07:33.155Z",
		UpdatedAt:       "2021-06-25T19:07:33.155Z",
	}

	userRes, err := CreateUser(context.Background(), CreateUserOpts{
		Email:         "marcelina@gmail.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		Password:      "pass",
		EmailVerified: false,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersAddUserToOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(addUserToOrganizationTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		UserType:        Unmanaged,
		Email:           "marcelina@foo-corp.com",
		FirstName:       "Marcelina",
		LastName:        "Davis",
		EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
		CreatedAt:       "2021-06-25T19:07:33.155Z",
		UpdatedAt:       "2021-06-25T19:07:33.155Z",
	}

	userRes, err := AddUserToOrganization(context.Background(), AddUserToOrganizationOpts{
		User:         "user_managed_id",
		Organization: "foo_corp_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersRemoveUserFromOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(removeUserFromOrganizationTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:              "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		UserType:        Unmanaged,
		Email:           "marcelina@foo-corp.com",
		FirstName:       "Marcelina",
		LastName:        "Davis",
		EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
		CreatedAt:       "2021-06-25T19:07:33.155Z",
		UpdatedAt:       "2021-06-25T19:07:33.155Z",
	}

	userRes, err := RemoveUserFromOrganization(context.Background(), RemoveUserFromOrganizationOpts{
		User:         "user_managed_id",
		Organization: "foo_corp_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersCreateEmailVerificationChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createEmailVerificationChallengeHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := CreateEmailVerificationChallengeResponse{
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
	}

	userRes, err := CreateEmailVerificationChallenge(context.Background(), CreateEmailVerificationChallengeOpts{
		User:            "user_unmanaged_id",
		VerificationUrl: "https://example.com/verify",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersCompleteEmailVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(completeEmailVerificationHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:              "user_unmanaged_id",
		UserType:        Unmanaged,
		Email:           "marcelina@foo-corp.com",
		FirstName:       "Marcelina",
		LastName:        "Davis",
		EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
	}

	userRes, err := CompleteEmailVerification(context.Background(), CompleteEmailVerificationOpts{
		Token: "testToken",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersCreatePasswordResetChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createPasswordResetChallengeHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := CreatePasswordResetChallengeResponse{
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
	}

	userRes, err := CreatePasswordResetChallenge(context.Background(), CreatePasswordResetChallengeOpts{
		Email:            "marcelina@foo-corp.com",
		PasswordResetUrl: "https://example.com/reset",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersCompletePasswordReset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(completePasswordResetHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:              "user_unmanaged_id",
		UserType:        Unmanaged,
		Email:           "marcelina@foo-corp.com",
		FirstName:       "Marcelina",
		LastName:        "Davis",
		EmailVerifiedAt: "2021-07-25T19:07:33.155Z",
	}

	userRes, err := CompletePasswordReset(context.Background(), CompletePasswordResetOpts{
		Token: "testToken",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersAuthenticateUserWithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getAuthenticationResponseHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := AuthenticationResponse{
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

	authenticationRes, err := AuthenticateUserWithToken(context.Background(), AuthenticateUserWithTokenOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersAuthenticateUserWithPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getAuthenticationResponseHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := AuthenticationResponse{
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

	authenticationRes, err := AuthenticateUserWithPassword(context.Background(), AuthenticateUserWithPasswordOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersVerifySession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getVerifySessionHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := VerifySessionResponse{
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

	sessionRes, err := VerifySession(context.Background(), VerifySessionOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, sessionRes)
}

func TestUsersRevokeSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getRevokeSessionHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := true

	sessionRes, err := RevokeSession(context.Background(), RevokeSessionOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, sessionRes)
}

func TestUsersRevokeAllSessionsForUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getRevokeSessionHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := true

	sessionRes, err := RevokeAllSessionsForUser(context.Background(), "123")

	require.NoError(t, err)
	require.Equal(t, expectedResponse, sessionRes)
}
