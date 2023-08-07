package users

import (
	"context"
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
