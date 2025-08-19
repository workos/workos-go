package directorysync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
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
				Directory: "directory_test",
			},
			expected: ListUsersResponse{
				Data: []User{
					User{
						ID:        "directory_user_id",
						FirstName: "Rick",
						LastName:  "Sanchez",
						JobTitle:  "Software Engineer",
						Email:     "rick@sanchez.com",
						Emails: []UserEmail{
							UserEmail{
								Primary: true,
								Type:    "work",
								Value:   "rick@sanchez.com",
							},
						},
						Groups: []UserGroup{
							UserGroup{
								Object: "user_group_object",
								ID:     "directory_group_123",
								Name:   "Group Name",
							},
						},
						State:            Active,
						RawAttributes:    json.RawMessage(`{"foo":"bar"}`),
						CustomAttributes: json.RawMessage(`{"foo":"bar"}`),
						Role: common.RoleResponse{
							Slug: "member",
						},
					},
				},
				ListMetadata: common.ListMetadata{
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
			Data: []User{
				User{
					ID:        "directory_user_id",
					FirstName: "Rick",
					LastName:  "Sanchez",
					JobTitle:  "Software Engineer",
					Email:     "rick@sanchez.com",
					Emails: []UserEmail{
						UserEmail{
							Primary: true,
							Type:    "work",
							Value:   "rick@sanchez.com",
						},
					},
					Groups: []UserGroup{
						UserGroup{
							Object: "user_group_object",
							ID:     "directory_group_123",
							Name:   "Group Name",
						},
					},
					State:            Active,
					RawAttributes:    json.RawMessage(`{"foo":"bar"}`),
					CustomAttributes: json.RawMessage(`{"foo":"bar"}`),
					Role:             common.RoleResponse{Slug: "member"},
				},
			},
			ListMetadata: common.ListMetadata{
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
				Directory: "directory_test",
			},
			expected: ListGroupsResponse{
				Data: []Group{
					Group{
						ID:             "directory_group_id",
						Name:           "Scientists",
						IdpID:          "123",
						DirectoryID:    "456",
						OrganizationID: "789",
						CreatedAt:      "2022-06-08T17:05:58.051Z",
						UpdatedAt:      "2022-06-08T17:05:58.051Z",
						RawAttributes:  json.RawMessage(`{"foo":"bar"}`),
					},
				},
				ListMetadata: common.ListMetadata{
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

			directoryGroups, err := client.ListGroups(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryGroups)
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
			Data: []Group{
				Group{
					ID:             "directory_group_id",
					Name:           "Scientists",
					IdpID:          "123",
					DirectoryID:    "456",
					OrganizationID: "789",
					CreatedAt:      "2022-06-08T17:05:58.051Z",
					UpdatedAt:      "2022-06-08T17:05:58.051Z",
					RawAttributes:  json.RawMessage(`{"foo":"bar"}`),
				},
			},
			ListMetadata: common.ListMetadata{
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
		expected User
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
				User: "directory_user_id",
			},
			expected: User{
				ID:        "directory_user_id",
				FirstName: "Rick",
				LastName:  "Sanchez",
				JobTitle:  "Software Engineer",
				Email:     "rick@sanchez.com",
				Emails: []UserEmail{
					UserEmail{
						Primary: true,
						Type:    "work",
						Value:   "rick@sanchez.com",
					},
				},
				Groups: []UserGroup{
					UserGroup{
						Object: "user_group_object",
						ID:     "directory_group_123",
						Name:   "Group Name",
					},
				},
				State:            Active,
				RawAttributes:    json.RawMessage(`{"foo":"bar"}`),
				CustomAttributes: json.RawMessage(`{"foo":"bar"}`),
				Role:             common.RoleResponse{Slug: "member"},
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

			directoryUser, err := client.GetUser(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryUser)
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

	body, err := json.Marshal(User{
		ID:        "directory_user_id",
		FirstName: "Rick",
		LastName:  "Sanchez",
		JobTitle:  "Software Engineer",
		Email:     "rick@sanchez.com",
		Emails: []UserEmail{
			UserEmail{
				Primary: true,
				Type:    "work",
				Value:   "rick@sanchez.com",
			},
		},
		Groups: []UserGroup{
			UserGroup{
				Object: "user_group_object",
				ID:     "directory_group_123",
				Name:   "Group Name",
			},
		},
		State:            Active,
		RawAttributes:    json.RawMessage(`{"foo":"bar"}`),
		CustomAttributes: json.RawMessage(`{"foo":"bar"}`),
		Role:             common.RoleResponse{Slug: "member"},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestGetGroup(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetGroupOpts
		expected Group
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Directory Group",
			client: &Client{
				APIKey: "test",
			},
			options: GetGroupOpts{
				Group: "directory_group_id",
			},
			expected: Group{
				ID:             "directory_group_id",
				Name:           "Scientists",
				IdpID:          "123",
				DirectoryID:    "456",
				OrganizationID: "789",
				CreatedAt:      "2022-06-08T17:05:58.051Z",
				UpdatedAt:      "2022-06-08T17:05:58.051Z",
				RawAttributes:  json.RawMessage(`{"foo":"bar"}`),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getGroupTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			directoryGroup, err := client.GetGroup(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directoryGroup)
		})
	}
}

func getGroupTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(Group{
		ID:             "directory_group_id",
		Name:           "Scientists",
		IdpID:          "123",
		DirectoryID:    "456",
		OrganizationID: "789",
		CreatedAt:      "2022-06-08T17:05:58.051Z",
		UpdatedAt:      "2022-06-08T17:05:58.051Z",
		RawAttributes:  json.RawMessage(`{"foo":"bar"}`),
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
				Data: []Directory{
					Directory{
						ID:          "directory_id",
						Name:        "Ri Jeong Hyeok",
						Domain:      "crashlandingyou.com",
						ExternalKey: "fried_chicken",
						State:       "linked",
						Type:        "gsuite directory",
					},
				},
				ListMetadata: common.ListMetadata{
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

			directories, err := client.ListDirectories(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, directories)
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
		Data: []Directory{
			Directory{
				ID:          "directory_id",
				Name:        "Ri Jeong Hyeok",
				Domain:      "crashlandingyou.com",
				ExternalKey: "fried_chicken",
				State:       "linked",
				Type:        "gsuite directory",
			},
		},
		ListMetadata: common.ListMetadata{
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

func TestDeleteDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteDirectoryTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:   "test",
		Endpoint: server.URL,
	}

	err := client.DeleteDirectory(context.TODO(), DeleteDirectoryOpts{
		Directory: "dir_12345",
	})
	require.NoError(t, err)
}

func TestDeleteDirectoryUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteDirectoryTestHandler))
	defer server.Close()

	client := &Client{
		Endpoint: server.URL,
	}

	err := client.DeleteDirectory(context.TODO(), DeleteDirectoryOpts{
		Directory: "dir_12345",
	})
	require.Error(t, err)
	t.Log(err)
}

func deleteDirectoryTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	userAgent := r.Header.Get("User-Agent")
	if !strings.HasPrefix(userAgent, "workos-go/") {
		http.Error(w, "bad user agent", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)

}

func TestListUsers_UnmarshalSnakeCaseListMetadata(t *testing.T) {
	raw := []byte(`{
        "data": [],
        "list_metadata": { "before": "", "after": "user_abc123" }
    }`)

	var resp ListUsersResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.Equal(t, "user_abc123", resp.ListMetadata.After)
	require.Equal(t, "", resp.ListMetadata.Before)
}

func TestListGroups_UnmarshalSnakeCaseListMetadata(t *testing.T) {
	raw := []byte(`{
        "data": [],
        "list_metadata": { "before": "", "after": "group_abc123" }
    }`)

	var resp ListGroupsResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.Equal(t, "group_abc123", resp.ListMetadata.After)
	require.Equal(t, "", resp.ListMetadata.Before)
}

func TestListDirectories_UnmarshalSnakeCaseListMetadata(t *testing.T) {
	raw := []byte(`{
        "data": [],
        "list_metadata": { "before": "", "after": "dir_abc123" }
    }`)

	var resp ListDirectoriesResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.Equal(t, "dir_abc123", resp.ListMetadata.After)
	require.Equal(t, "", resp.ListMetadata.Before)
}
