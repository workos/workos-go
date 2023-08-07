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
		OrganizationMemberships: []OrganizationMembership{
			{
				Organization: Organization{
					ID:   "org_01E4ZCR3C56J083X43JQXF3JK5",
					Name: "Foo Corp",
				},
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
			},
		},
		CreatedAt: "2021-06-25T19:07:33.155Z",
		UpdatedAt: "2021-06-25T19:07:33.155Z",
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
				OrganizationMemberships: []OrganizationMembership{
					{
						Organization: Organization{
							ID:   "org_01E4ZCR3C56J083X43JQXF3JK5",
							Name: "Marcelina's Workspace",
						},
						CreatedAt: "2021-06-25T19:07:33.155Z",
						UpdatedAt: "2021-06-25T19:07:33.155Z",
					},
					{
						Organization: Organization{
							ID:   "org_01E4ZCR3C56J083X43JQXF3JK5",
							Name: "David's Workspace",
						},
						CreatedAt: "2021-06-25T19:07:33.155Z",
						UpdatedAt: "2021-06-25T19:07:33.155Z",
					},
				},
				CreatedAt: "2021-06-25T19:07:33.155Z",
				UpdatedAt: "2021-06-25T19:07:33.155Z",
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
