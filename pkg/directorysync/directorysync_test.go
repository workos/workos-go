package directorysync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
)

func TestDirectorySyncListUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listUsersTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListUsersResponse{
		Data: []User{
			User{
				ID:        "directory_user_id",
				FirstName: "Rick",
				LastName:  "Sanchez",
				JobTitle:  "Software Engineer",
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
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}
	directoryUsersResponse, err := ListUsers(context.Background(), ListUsersOpts{
		Directory: "directory_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryUsersResponse)
}

func TestDirectorySyncListGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listGroupsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListGroupsResponse{
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
	}
	directoryGroupsResponse, err := ListGroups(
		context.Background(),
		ListGroupsOpts{
			Directory: "directory_id",
		},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryGroupsResponse)
}

func TestDirectorySyncGetUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getUserTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := User{
		ID:        "directory_user_id",
		FirstName: "Rick",
		LastName:  "Sanchez",
		JobTitle:  "Software Engineer",
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
	}
	directoryUserResponse, err := GetUser(context.Background(), GetUserOpts{
		User: "directory_user_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryUserResponse)
}

func TestDirectorySyncGetGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getGroupTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Group{
		ID:             "directory_group_id",
		Name:           "Scientists",
		IdpID:          "123",
		DirectoryID:    "456",
		OrganizationID: "789",
		CreatedAt:      "2022-06-08T17:05:58.051Z",
		UpdatedAt:      "2022-06-08T17:05:58.051Z",
		RawAttributes:  json.RawMessage(`{"foo":"bar"}`),
	}
	directoryGroupResponse, err := GetGroup(context.Background(), GetGroupOpts{
		Group: "directory_group_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryGroupResponse)
}

func TestDirectorySyncListDirectories(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listDirectoriesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListDirectoriesResponse{
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
	}
	directoriesResponse, err := ListDirectories(
		context.Background(),
		ListDirectoriesOpts{},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoriesResponse)
}

func TestDirectorySyncDeleteDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteDirectoryTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteDirectory(
		context.Background(),
		DeleteDirectoryOpts{
			Directory: "dir_12345",
		},
	)

	require.NoError(t, err)
}

func TestGetDirectory(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetDirectoryOpts
		expected Directory
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns an Directory",
			client: &Client{
				APIKey: "test",
			},
			options: GetDirectoryOpts{
				Directory: "Directory_id",
			},
			expected: Directory{
				ID:          "directory_id",
				Name:        "Ri Jeong Hyeok",
				Domain:      "crashlandingyou.com",
				ExternalKey: "fried_chicken",
				State:       "linked",
				Type:        "gsuite directory",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getDirectoryTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			Directory, err := client.GetDirectory(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, Directory)
		})
	}
}

func getDirectoryTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(Directory{
		ID:          "directory_id",
		Name:        "Ri Jeong Hyeok",
		Domain:      "crashlandingyou.com",
		ExternalKey: "fried_chicken",
		State:       "linked",
		Type:        "gsuite directory",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestPrimaryEmail(t *testing.T) {
	tests := []struct {
		scenario string
		user     User
		expected string
		err      bool
	}{
		{
			scenario: "One primary email returns primary email",
			user: User{
				ID:        "directory_user_id",
				FirstName: "WorkOS",
				LastName:  "Testz",
				Emails: []UserEmail{
					UserEmail{
						Primary: true,
						Type:    "work",
						Value:   "primaryemail@foo-corp.com",
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
			},
			expected: "primaryemail@foo-corp.com",
		},
		{
			scenario: "Multiple primary emails returns the first primary email",
			user: User{
				ID:        "directory_user_id",
				FirstName: "WorkOS",
				LastName:  "Testz",
				Emails: []UserEmail{
					UserEmail{
						Primary: true,
						Type:    "work",
						Value:   "firstprimaryemail@foo-corp.com",
					},
					UserEmail{
						Primary: true,
						Type:    "work",
						Value:   "primaryemail@foo-corp.com",
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
			},
			expected: "firstprimaryemail@foo-corp.com",
		},
		{
			scenario: "No primary emails returns null and an error",
			user: User{
				ID:        "directory_user_id",
				FirstName: "WorkOS",
				LastName:  "Testz",
				Emails: []UserEmail{
					UserEmail{
						Type:  "work",
						Value: "firstprimaryemail@foo-corp.com",
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
			},
			err: true,
		},
		{
			scenario: "No emails returns null",
			user: User{
				ID:        "directory_user_id",
				FirstName: "WorkOS",
				LastName:  "Testz",
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
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			user := test.user

			primaryemail, err := user.PrimaryEmail()
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, primaryemail)
		})
	}
}
