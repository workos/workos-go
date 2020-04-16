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

func TestGetDirectoryUsers(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetDirectoryUsersOpts
		expected GetDirectoryUsersResponse
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
			options: GetDirectoryUsersOpts{
				DirectoryEndpointID: "directory_edp_test",
			},
			expected: GetDirectoryUsersResponse{
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
			server := httptest.NewServer(http.HandlerFunc(getDirectoryUsersTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.GetDirectoryUsers(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func getDirectoryUsersTestHandler(w http.ResponseWriter, r *http.Request) {
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
		GetDirectoryUsersResponse
	}{
		GetDirectoryUsersResponse: GetDirectoryUsersResponse{
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

func TestGetDirectoryGroups(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetDirectoryGroupsOpts
		expected GetDirectoryGroupsResponse
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
			options: GetDirectoryGroupsOpts{
				DirectoryEndpointID: "directory_edp_test",
			},
			expected: GetDirectoryGroupsResponse{
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
			server := httptest.NewServer(http.HandlerFunc(getDirectoryGroupsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.GetDirectoryGroups(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func getDirectoryGroupsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		GetDirectoryGroupsResponse
	}{
		GetDirectoryGroupsResponse: GetDirectoryGroupsResponse{
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

func TestGetDirectoryUserGroups(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetDirectoryUserGroupsOpts
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
			options: GetDirectoryUserGroupsOpts{
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
			server := httptest.NewServer(http.HandlerFunc(getDirectoryUserGroupsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.GetDirectoryUserGroups(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func getDirectoryUserGroupsTestHandler(w http.ResponseWriter, r *http.Request) {
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

func TestGetDirectories(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetDirectoriesOpts
		expected GetDirectoriesResponse
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
			options: GetDirectoriesOpts{},
			expected: GetDirectoriesResponse{
				Data: []DirectoryEndpoint{
					DirectoryEndpoint{
						ID:          "directory_edp_id",
						Name:        "Ri Jeong Hyeok",
						Domain:      "crashlanding@you.com",
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
			server := httptest.NewServer(http.HandlerFunc(getDirectoriesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryUsers, err := client.GetDirectories(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUsers)
		})
	}
}

func getDirectoriesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(GetDirectoriesResponse{
		Data: []DirectoryEndpoint{
			DirectoryEndpoint{
				ID:          "directory_edp_id",
				Name:        "Ri Jeong Hyeok",
				Domain:      "crashlanding@you.com",
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
