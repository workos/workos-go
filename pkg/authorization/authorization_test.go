package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestAuthorizationCreatePermission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, Permission{
		Object:           "permission",
		Id:               "perm_01HXYZ",
		Slug:             "documents.read",
		Name:             "Read Documents",
		Description:      "Allows reading documents",
		ResourceTypeSlug: "document",
		System:           false,
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	})))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Permission{
		Object:           "permission",
		Id:               "perm_01HXYZ",
		Slug:             "documents.read",
		Name:             "Read Documents",
		Description:      "Allows reading documents",
		ResourceTypeSlug: "document",
		System:           false,
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	}

	result, err := CreatePermission(context.Background(), CreatePermissionOpts{
		Slug:             "documents.read",
		Name:             "Read Documents",
		Description:      "Allows reading documents",
		ResourceTypeSlug: "document",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationListPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listResponseHandler(nil, nil, ListPermissionsResponse{
		Data: []Permission{
			{
				Object:    "permission",
				Id:        "perm_01HXYZ",
				Slug:      "documents.read",
				Name:      "Read Documents",
				System:    false,
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
			{
				Object:    "permission",
				Id:        "perm_02HXYZ",
				Slug:      "documents.write",
				Name:      "Write Documents",
				System:    false,
				CreatedAt: "2024-01-02T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	})))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListPermissionsResponse{
		Data: []Permission{
			{
				Object:    "permission",
				Id:        "perm_01HXYZ",
				Slug:      "documents.read",
				Name:      "Read Documents",
				System:    false,
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
			{
				Object:    "permission",
				Id:        "perm_02HXYZ",
				Slug:      "documents.write",
				Name:      "Write Documents",
				System:    false,
				CreatedAt: "2024-01-02T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}

	result, err := ListPermissions(context.Background(), ListPermissionsOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationGetPermission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	})))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}

	result, err := GetPermission(context.Background(), GetPermissionOpts{
		Slug: "documents.read",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationUpdatePermission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read All Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	})))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read All Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	}

	newName := "Read All Documents"
	result, err := UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "documents.read",
		Name: &newName,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationDeletePermission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, nil)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeletePermission(context.Background(), DeletePermissionOpts{
		Slug: "documents.read",
	})

	require.NoError(t, err)
}
