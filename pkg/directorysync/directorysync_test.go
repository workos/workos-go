package directorysync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
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
	directoryUsersResponse, err := ListUsers(context.Background(), ListUsersOpts{
		DirectoryEndpointID: "directory_edp_id",
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
	directoryGroupsResponse, err := ListGroups(
		context.Background(),
		ListGroupsOpts{
			DirectoryEndpointID: "directory_edp_id",
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
	directoryUserResponse, err := GetUser(context.Background(), GetUserOpts{
		DirectoryEndpointID: "directory_edp_id",
		DirectoryUserID:     "directory_usr_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryUserResponse)
}

func TestDirectorySyncListUserGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listUserGroupsTestHandler))
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
	directoryUserGroupsResponse, err := ListUserGroups(
		context.Background(),
		ListUserGroupsOpts{
			DirectoryEndpointID: "directory_edp_id",
			DirectoryUserID:     "directory_usr_id",
		},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoryUserGroupsResponse)
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
	}
	directoriesResponse, err := ListDirectories(
		context.Background(),
		ListDirectoriesOpts{},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, directoriesResponse)
}
