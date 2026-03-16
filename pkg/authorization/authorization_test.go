package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestAuthorizationListOrganizationRoles(t *testing.T) {
	expectedResponse := ListOrganizationRolesResponse{
		Data: []OrganizationRole{
			{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Admin",
				Slug:        "org-admin",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(
		jsonResponseHandler(nil, nil, expectedResponse),
	))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	result, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationCreateOrganizationRole(t *testing.T) {
	desc := "Can manage the organization"
	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Description: &desc,
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	}

	server := httptest.NewServer(http.HandlerFunc(
		jsonResponseHandler(nil, nil, expectedResponse),
	))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	result, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
		Name:           "Org Admin",
		Description:    "Can manage the organization",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationGetOrganizationRole(t *testing.T) {
	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "org-admin",
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	}

	server := httptest.NewServer(http.HandlerFunc(
		jsonResponseHandler(nil, nil, expectedResponse),
	))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	result, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationUpdateOrganizationRole(t *testing.T) {
	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Super Admin",
		Slug:        "org-admin",
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	}

	server := httptest.NewServer(http.HandlerFunc(
		jsonResponseHandler(nil, nil, expectedResponse),
	))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	name := "Super Admin"
	result, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
		Name:           &name,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationDeleteOrganizationRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		noContentHandler(nil, nil),
	))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
	})

	require.NoError(t, err)
}
