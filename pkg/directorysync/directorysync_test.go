package directorysync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectorySyncGetUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getDirectoryUsersTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := GetDirectoryUsersResponse{
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
	}
	directoryUsersResponse, err := GetDirectoryUsers(context.Background(), GetDirectoryUsersOpts{
		DirectoryEndpointID: "directory_edp_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryUsersResponse)
}

func TestDirectorySyncGetGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getDirectoryGroupsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := GetDirectoryGroupsResponse{
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
	}
	directoryGroupsResponse, err := GetDirectoryGroups(
		context.Background(),
		GetDirectoryGroupsOpts{
			DirectoryEndpointID: "directory_edp_id",
		},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryGroupsResponse)
}

func TestDirectorySyncGetUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getDirectoryUserTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := DirectoryUser{
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
	}
	directoryUserResponse, err := GetDirectoryUser(context.Background(), GetDirectoryUserOpts{
		DirectoryEndpointID: "directory_edp_id",
		DirectoryUserID:     "directory_usr_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryUserResponse)
}

func TestDirectorySyncGetUserGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getDirectoryUserGroupsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := []DirectoryGroup{
		DirectoryGroup{
			ID:   "directory_grp_id",
			Name: "Scientists",
		},
	}
	directoryUserGroupsResponse, err := GetDirectoryUserGroups(
		context.Background(),
		GetDirectoryUserGroupsOpts{
			DirectoryEndpointID: "directory_edp_id",
			DirectoryUserID:     "directory_usr_id",
		},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryUserGroupsResponse)
}

func TestDirectorySyncGetDirectories(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getDirectoriesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := GetDirectoriesResponse{
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
	}
	directoriesResponse, err := GetDirectories(
		context.Background(),
		GetDirectoriesOpts{},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoriesResponse)
}
