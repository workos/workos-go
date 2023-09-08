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
		ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
		CreatedAt:     "2021-06-25T19:07:33.155Z",
		UpdatedAt:     "2021-06-25T19:07:33.155Z",
	}

	userRes, err := GetUser(context.Background(), GetUserOpts{
		User: "user_123",
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
		ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
		CreatedAt:     "2021-06-25T19:07:33.155Z",
		UpdatedAt:     "2021-06-25T19:07:33.155Z",
	}

	userRes, err := CreateUser(context.Background(), CreateUserOpts{
		Email:         "marcelina@gmail.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
		Password:      "pass",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersUpdateUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateUserTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
		CreatedAt:     "2021-06-25T19:07:33.155Z",
		UpdatedAt:     "2021-06-25T19:07:33.155Z",
	}

	userRes, err := UpdateUser(context.Background(), UpdateUserOpts{
		User:          "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersUpdateUserPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateUserPasswordTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
		CreatedAt:     "2021-06-25T19:07:33.155Z",
		UpdatedAt:     "2021-06-25T19:07:33.155Z",
	}

	userRes, err := UpdateUserPassword(context.Background(), UpdateUserPasswordOpts{
		User:     "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Password: "pass_123",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersDeleteUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteUserTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	err := DeleteUser(context.Background(), DeleteUserOpts{
		User: "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
	})

	require.NoError(t, err)
	require.Equal(t, nil, err)
}

func TestUsersAddUserToOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(addUserToOrganizationTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := User{
		ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
		CreatedAt:     "2021-06-25T19:07:33.155Z",
		UpdatedAt:     "2021-06-25T19:07:33.155Z",
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
		ID:            "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
		CreatedAt:     "2021-06-25T19:07:33.155Z",
		UpdatedAt:     "2021-06-25T19:07:33.155Z",
	}

	userRes, err := RemoveUserFromOrganization(context.Background(), RemoveUserFromOrganizationOpts{
		User:         "user_managed_id",
		Organization: "foo_corp_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersSendVerificationEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(sendVerificationEmailTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:            "user_123",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
			CreatedAt:     "2021-06-25T19:07:33.155Z",
			UpdatedAt:     "2021-06-25T19:07:33.155Z",
		},
	}

	userRes, err := SendVerificationEmail(context.Background(), SendVerificationEmailOpts{
		User: "user_123",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersVerifyEmailCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(verifyEmailCodeTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:            "user_123",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
		},
	}

	userRes, err := VerifyEmailCode(context.Background(), VerifyEmailCodeOpts{
		User: "user_123",
		Code: "testToken",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersCreatePasswordResetChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createPasswordResetChallengeHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:            "user_123",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
			CreatedAt:     "2021-06-25T19:07:33.155Z",
			UpdatedAt:     "2021-06-25T19:07:33.155Z",
		},
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
		ID:            "user_123",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
	}

	userRes, err := CompletePasswordReset(context.Background(), CompletePasswordResetOpts{
		Token: "testToken",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersAuthenticateUserWithCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := AuthenticationResponse{
		User: User{
			ID:        "testUserID",
			FirstName: "John",
			LastName:  "Doe",
			Email:     "employee@foo-corp.com",
		},
	}

	authenticationRes, err := AuthenticateUserWithCode(context.Background(), AuthenticateUserWithCodeOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersAuthenticateUserWithPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := AuthenticationResponse{
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
