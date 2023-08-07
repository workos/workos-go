package users

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
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
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns a managed User",
			client: &Client{
				APIKey: "test",
			},
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
			},
		},
		{
			scenario: "Request returns an unmanaged User",
			client: &Client{
				APIKey: "test",
			},
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
		})
	} else if r.URL.Path == "/users/user_unmanaged_id" {
		body, err = json.Marshal(User{
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
		})
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
