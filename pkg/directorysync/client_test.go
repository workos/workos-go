package directorysync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListUsers(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListUsersOpts
		expected ListUsersResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Directory Users",
			client: &Client{
				APIKey: "test",
			},
			options: ListUsersOpts{
				DirectoryEndpointID: "directory_edp_test",
			},
			expected: ListUsersResponse{
				Data: []DirectoryUser{
					DirectoryUser{
						ID:        "directory_usr_id",
						FirstName: "Rick",
						LastName:  "Sanchez",
						Emails: []DirectoryUserEmail{
							DirectoryUserEmail{
								Primary: true,
								Type:    "work",
								Value:   "rick@sanchez.com",
							},
						},
						RawAttributes: json.RawMessage(`{"foo":"bar"}`),
					},
				},
				ListMetadata: ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listUsersTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.ListUsers(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
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
			Data: []DirectoryUser{
				DirectoryUser{
					ID:        "directory_usr_id",
					FirstName: "Rick",
					LastName:  "Sanchez",
					Emails: []DirectoryUserEmail{
						DirectoryUserEmail{
							Primary: true,
							Type:    "work",
							Value:   "rick@sanchez.com",
						},
					},
					RawAttributes: json.RawMessage(`{"foo":"bar"}`),
				},
			},
			ListMetadata: ListMetadata{
				Before: "",
				After:  "",
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

func TestListGroups(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListGroupsOpts
		expected ListGroupsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Directory Groups",
			client: &Client{
				APIKey: "test",
			},
			options: ListGroupsOpts{
				DirectoryEndpointID: "directory_edp_test",
			},
			expected: ListGroupsResponse{
				Data: []DirectoryGroup{
					DirectoryGroup{
						ID:   "directory_grp_id",
						Name: "Scientists",
					},
				},
				ListMetadata: ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listGroupsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.ListGroups(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func listGroupsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListGroupsResponse
	}{
		ListGroupsResponse: ListGroupsResponse{
			Data: []DirectoryGroup{
				DirectoryGroup{
					ID:   "directory_grp_id",
					Name: "Scientists",
				},
			},
			ListMetadata: ListMetadata{
				Before: "",
				After:  "",
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

func TestGetUser(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetUserOpts
		expected DirectoryUser
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Directory User",
			client: &Client{
				APIKey: "test",
			},
			options: GetUserOpts{
				DirectoryEndpointID: "directory_edp_id",
				DirectoryUserID:     "directory_usr_id",
			},
			expected: DirectoryUser{
				ID:        "directory_usr_id",
				FirstName: "Rick",
				LastName:  "Sanchez",
				Emails: []DirectoryUserEmail{
					DirectoryUserEmail{
						Primary: true,
						Type:    "work",
						Value:   "rick@sanchez.com",
					},
				},
				RawAttributes: json.RawMessage(`{"foo":"bar"}`),
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

			directoryUsers, err := client.GetUser(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func getUserTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(DirectoryUser{
		ID:        "directory_usr_id",
		FirstName: "Rick",
		LastName:  "Sanchez",
		Emails: []DirectoryUserEmail{
			DirectoryUserEmail{
				Primary: true,
				Type:    "work",
				Value:   "rick@sanchez.com",
			},
		},
		RawAttributes: json.RawMessage(`{"foo":"bar"}`),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListUserGroups(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListUserGroupsOpts
		expected []DirectoryGroup
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Directory User's Groups",
			client: &Client{
				APIKey: "test",
			},
			options: ListUserGroupsOpts{
				DirectoryEndpointID: "directory_edp_id",
				DirectoryUserID:     "directory_usr_id",
			},
			expected: []DirectoryGroup{
				DirectoryGroup{
					ID:   "directory_grp_id",
					Name: "Scientists",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listUserGroupsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.ListUserGroups(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func listUserGroupsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal([]DirectoryGroup{
		DirectoryGroup{
			ID:   "directory_grp_id",
			Name: "Scientists",
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListDirectories(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListDirectoriesOpts
		expected ListDirectoriesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Directories",
			client: &Client{
				APIKey: "test",
			},
			options: ListDirectoriesOpts{},
			expected: ListDirectoriesResponse{
				Data: []DirectoryEndpoint{
					DirectoryEndpoint{
						ID:          "directory_edp_id",
						Name:        "Ri Jeong Hyeok",
						Domain:      "crashlandingyou.com",
						ExternalKey: "fried_chicken",
						State:       "linked",
						Type:        "gsuite directory",
						ProjectID:   "project_id",
					},
				},
				ListMetadata: ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listDirectoriesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.ListDirectories(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func listDirectoriesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListDirectoriesResponse{
		Data: []DirectoryEndpoint{
			DirectoryEndpoint{
				ID:          "directory_edp_id",
				Name:        "Ri Jeong Hyeok",
				Domain:      "crashlandingyou.com",
				ExternalKey: "fried_chicken",
				State:       "linked",
				Type:        "gsuite directory",
				ProjectID:   "project_id",
			},
		},
		ListMetadata: ListMetadata{
			Before: "",
			After:  "",
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
