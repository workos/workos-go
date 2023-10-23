package users

import (
	"context"
	"github.com/workos/workos-go/v2/pkg/common"
	"github.com/workos/workos-go/v2/pkg/mfa"
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
	server := httptest.NewServer(http.HandlerFunc(sendPasswordResetEmailTestHandler))
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

	userRes, err := SendPasswordResetEmail(context.Background(), SendPasswordResetEmailOpts{
		Email:            "marcelina@foo-corp.com",
		PasswordResetUrl: "https://example.com/reset",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersResetPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(resetPasswordHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID: "user_123",

			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
		},
	}

	userRes, err := ResetPassword(context.Background(), ResetPasswordOpts{
		Token: "testToken",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersAuthenticateWithCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:        "testUserID",
			FirstName: "John",
			LastName:  "Doe",
			Email:     "employee@foo-corp.com",
		},
	}

	authenticationRes, err := AuthenticateWithCode(context.Background(), AuthenticateWithCodeOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersAuthenticateWithPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:        "testUserID",
			FirstName: "John",
			LastName:  "Doe",
			Email:     "employee@foo-corp.com",
		},
	}

	authenticationRes, err := AuthenticateWithPassword(context.Background(), AuthenticateWithPasswordOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersAuthenticateWithMagicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:        "testUserID",
			FirstName: "John",
			LastName:  "Doe",
			Email:     "employee@foo-corp.com",
		},
	}

	authenticationRes, err := AuthenticateWithMagicAuth(context.Background(), AuthenticateWithMagicAuthOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersAuthenticateWithTOTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(authenticationResponseTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:        "testUserID",
			FirstName: "John",
			LastName:  "Doe",
			Email:     "employee@foo-corp.com",
		},
	}

	authenticationRes, err := AuthenticateWithTOTP(context.Background(), AuthenticateWithTOTPOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersSendMagicAuthCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(sendMagicAuthCodeTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := UserResponse{
		User: User{
			ID:        "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
			Email:     "marcelina@foo-corp.com",
			FirstName: "Marcelina",
			LastName:  "Davis",
			CreatedAt: "2021-06-25T19:07:33.155Z",
			UpdatedAt: "2021-06-25T19:07:33.155Z",
		},
	}

	authenticationRes, err := SendMagicAuthCode(context.Background(), SendMagicAuthCodeOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersEnrollAuthFactor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(enrollAuthFactorTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := AuthenticationResponse{
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
	}

	authenticationRes, err := EnrollAuthFactor(context.Background(), EnrollAuthFactorOpts{
		User: "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
		Type: mfa.TOTP,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersListAuthFactors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listAuthFactorsTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := ListAuthFactorsResponse{
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
	}

	authenticationRes, err := ListAuthFactors(context.Background(), ListAuthFactorsOpts{
		User: "user_01E3JC5F5Z1YJNPGVYWV9SX6GH",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, authenticationRes)
}

func TestUsersCreateInvitation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createInvitationTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := InviteObject{
		Object:    "invite",
		ID:        "invite_123",
		Email:     "marcelina@foo-corp.com",
		State:     "pending",
		Token:     "myToken",
		ExpiresAt: "2021-06-25T19:07:33.155Z",
		CreatedAt: "2021-06-25T19:07:33.155Z",
		UpdatedAt: "2021-06-25T19:07:33.155Z",
	}

	createRes, err := CreateInvitation(context.Background(), CreateInvitationOpts{
		Email:          "marcelina@foo-corp.com",
		OrganizationID: "org_123",
		ExpiresInDays:  7,
		InviterUserID:  "user_123",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, createRes)
}

func TestUsersRevokeInvitation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(revokeInvitationTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := InviteObject{
		Object:    "invite",
		ID:        "invite_123",
		Email:     "marcelina@foo-corp.com",
		State:     "pending",
		Token:     "myToken",
		ExpiresAt: "2021-06-25T19:07:33.155Z",
		CreatedAt: "2021-06-25T19:07:33.155Z",
		UpdatedAt: "2021-06-25T19:07:33.155Z",
	}

	revokeRes, err := RevokeInvitation(context.Background(), RevokeInvitationOpts{
		InviteID: "invite_123",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, revokeRes)
}
