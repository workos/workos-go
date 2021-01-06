package directorysync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos-inc/workos-go/pkg/common"
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
				ID:        "directory_usr_id",
				FirstName: "Rick",
				LastName:  "Sanchez",
				Emails: []UserEmail{
					UserEmail{
						Primary: true,
						Type:    "work",
						Value:   "rick@sanchez.com",
					},
				},
				RawAttributes: json.RawMessage(`{"foo":"bar"}`),
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
				ID:   "directory_grp_id",
				Name: "Scientists",
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
		ID:        "directory_usr_id",
		FirstName: "Rick",
		LastName:  "Sanchez",
		Emails: []UserEmail{
			UserEmail{
				Primary: true,
				Type:    "work",
				Value:   "rick@sanchez.com",
			},
		},
		RawAttributes: json.RawMessage(`{"foo":"bar"}`),
	}
	directoryUserResponse, err := GetUser(context.Background(), GetUserOpts{
		User: "directory_usr_id",
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
		ID:   "directory_grp_id",
		Name: "Scientists",
	}
	directoryGroupResponse, err := GetGroup(context.Background(), GetGroupOpts{
		Group: "directory_grp_id",
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
				ID:            "directory_id",
				Name:          "Ri Jeong Hyeok",
				Domain:        "crashlandingyou.com",
				ExternalKey:   "fried_chicken",
				State:         "linked",
				Type:          "gsuite directory",
				EnvironmentID: "environment_id",
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
