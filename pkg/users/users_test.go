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

func TestUsersCreateEmailVerificationChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createEmailVerificationChallengeHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	SetAPIKey("test")

	expectedResponse := ChallengeResponse{
		User: User{
			ID:            "user_123",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
			CreatedAt:     "2021-06-25T19:07:33.155Z",
			UpdatedAt:     "2021-06-25T19:07:33.155Z",
		},
		Token: "testToken",
	}

	userRes, err := CreateEmailVerificationChallenge(context.Background(), CreateEmailVerificationChallengeOpts{
		User:            "user_123",
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
		ID:            "user_123",
		Email:         "marcelina@foo-corp.com",
		FirstName:     "Marcelina",
		LastName:      "Davis",
		EmailVerified: true,
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

	expectedResponse := ChallengeResponse{
		User: User{
			ID:            "user_123",
			Email:         "marcelina@foo-corp.com",
			FirstName:     "Marcelina",
			LastName:      "Davis",
			EmailVerified: true,
			CreatedAt:     "2021-06-25T19:07:33.155Z",
			UpdatedAt:     "2021-06-25T19:07:33.155Z",
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
		Session: Session{
			ID:        "testSessionID",
			Token:     "testSessionToken",
			CreatedAt: "2023-08-05T14:48:00.000Z",
			ExpiresAt: "2023-08-05T14:50:00.000Z",
			AuthorizedOrganizations: []AuthorizedOrganization{
				{
					Organization: Organization{
						ID:   "123",
						Name: "Example",
					},
				},
			},
			UnauthorizedOrganizations: []UnauthorizedOrganization{
				{
					Organization: Organization{
						ID:   "123",
						Name: "Example",
					},
					Reasons: []UnauthorizedOrganizationReason{
						{
							Type: "authentication_method_required",
							AllowedAuthenticationMethods: []SessionAuthenticationMethod{
								MagicAuth,
								Password,
							},
						},
					},
				},
			},
		},
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
		Session: Session{
			ID:        "testSessionID",
			Token:     "testSessionToken",
			CreatedAt: "2023-08-05T14:48:00.000Z",
			ExpiresAt: "2023-08-05T14:50:00.000Z",
			AuthorizedOrganizations: []AuthorizedOrganization{
				{
					Organization: Organization{
						ID:   "123",
						Name: "Example",
					},
				},
			},
			UnauthorizedOrganizations: []UnauthorizedOrganization{
				{
					Organization: Organization{
						ID:   "123",
						Name: "Example",
					},
					Reasons: []UnauthorizedOrganizationReason{
						{
							Type: "authentication_method_required",
							AllowedAuthenticationMethods: []SessionAuthenticationMethod{
								MagicAuth,
								Password,
							},
						},
					},
				},
			},
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
