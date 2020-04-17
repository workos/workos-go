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

func TestListDirectoryUsers(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListDirectoryUsersOpts
		expected ListDirectoryUsersResponse
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
			options: ListDirectoryUsersOpts{
				DirectoryEndpointID: "directory_edp_test",
			},
			expected: ListDirectoryUsersResponse{
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
			server := httptest.NewServer(http.HandlerFunc(listDirectoryUsersTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.ListDirectoryUsers(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func listDirectoryUsersTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListDirectoryUsersResponse
	}{
		ListDirectoryUsersResponse: ListDirectoryUsersResponse{
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

func TestListDirectoryGroups(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListDirectoryGroupsOpts
		expected ListDirectoryGroupsResponse
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
			options: ListDirectoryGroupsOpts{
				DirectoryEndpointID: "directory_edp_test",
			},
			expected: ListDirectoryGroupsResponse{
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
			server := httptest.NewServer(http.HandlerFunc(listDirectoryGroupsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.ListDirectoryGroups(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func listDirectoryGroupsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListDirectoryGroupsResponse
	}{
		ListDirectoryGroupsResponse: ListDirectoryGroupsResponse{
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

func TestGetDirectoryUser(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetDirectoryUserOpts
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
			options: GetDirectoryUserOpts{
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
			server := httptest.NewServer(http.HandlerFunc(getDirectoryUserTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.GetDirectoryUser(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func getDirectoryUserTestHandler(w http.ResponseWriter, r *http.Request) {
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

func TestListDirectoryUserGroups(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListDirectoryUserGroupsOpts
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
			options: ListDirectoryUserGroupsOpts{
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
			server := httptest.NewServer(http.HandlerFunc(listDirectoryUserGroupsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.ListDirectoryUserGroups(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func listDirectoryUserGroupsTestHandler(w http.ResponseWriter, r *http.Request) {
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
