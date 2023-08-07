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
				OrganizationMemberships: []OrganizationMembership{
					{
						Organization: Organization{
							ID:   "foo_corp_id",
							Name: "Marcelina's Workspace",
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
			OrganizationMemberships: []OrganizationMembership{
				{
					Organization: Organization{
						ID:   "foo_corp_id",
						Name: "Marcelina's Workspace",
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
