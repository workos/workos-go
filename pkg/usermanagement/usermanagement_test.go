package usermanagement

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/workos/workos-go/v3/pkg/common"
	"github.com/workos/workos-go/v3/pkg/mfa"

	"github.com/stretchr/testify/require"
)

func mockClient(s *httptest.Server) *Client {
	client := NewClient("")
	client.HTTPClient = s.Client()
	client.Endpoint = s.URL
	return client
}

func TestUserManagementGetUser(t *testing.T) {
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

func TestUserManagementListUsers(t *testing.T) {
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

func TestUserManagementCreateUser(t *testing.T) {
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

func TestUserManagementUpdateUser(t *testing.T) {
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

func TestUserManagementVerifyEmail(t *testing.T) {
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

	userRes, err := VerifyEmail(context.Background(), VerifyEmailOpts{
		User: "user_123",
		Code: "testToken",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUserManagementCreatePasswordResetChallenge(t *testing.T) {
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

func TestUserManagementResetPassword(t *testing.T) {
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

func TestUserManagementAuthenticateWithCode(t *testing.T) {
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

func TestUserManagementAuthenticateWithPassword(t *testing.T) {
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

func TestUserManagementAuthenticateWithMagicAuth(t *testing.T) {
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

func TestUserManagementAuthenticateWithTOTP(t *testing.T) {
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

func TestUserManagementSendMagicAuthCode(t *testing.T) {
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

func TestUserManagementEnrollAuthFactor(t *testing.T) {
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

func TestUserManagementListAuthFactors(t *testing.T) {
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

func TestUserManagementGetOrganizationMembership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getOrganizationMembershipTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := OrganizationMembership{
		ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
		UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
		OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
		CreatedAt:      "2021-06-25T19:07:33.155Z",
		UpdatedAt:      "2021-06-25T19:07:33.155Z",
	}

	userRes, err := GetOrganizationMembership(context.Background(), GetOrganizationMembershipOpts{
		OrganizationMembershipID: "om_01E4ZCR3C56J083X43JQXF3JK5",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUserManagementListOrganizationMemberships(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listOrganizationMembershipsTestHandler))

	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := ListOrganizationMembershipsResponse{
		Data: []OrganizationMembership{
			{
				ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
				UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
				OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
				CreatedAt:      "2021-06-25T19:07:33.155Z",
				UpdatedAt:      "2021-06-25T19:07:33.155Z",
			},
		},
		ListMetadata: common.ListMetadata{
			After: "",
		},
	}

	userRes, err := ListOrganizationMemberships(context.Background(), ListOrganizationMembershipsOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUserManagementCreateOrganizationMembership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createOrganizationMembershipTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := OrganizationMembership{
		ID:             "om_01E4ZCR3C56J083X43JQXF3JK5",
		UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
		OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
		CreatedAt:      "2021-06-25T19:07:33.155Z",
		UpdatedAt:      "2021-06-25T19:07:33.155Z",
	}

	userRes, err := CreateOrganizationMembership(context.Background(), CreateOrganizationMembershipOpts{
		UserID:         "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
		OrganizationID: "org_01E4ZCR3C56J083X43JQXF3JK5",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, userRes)
}

func TestUsersDeleteOrganizationMembership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteOrganizationMembershipTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	err := DeleteOrganizationMembership(context.Background(), DeleteOrganizationMembershipOpts{
		OrganizationMembershipID: "om_01E4ZCR3C56J083X43JQXF3JK5",
	})

	require.NoError(t, err)
	require.Equal(t, nil, err)
}
