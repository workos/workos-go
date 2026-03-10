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

func TestAuthorizationCreateResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createResourceWithoutParentTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "resource_new",
		ExternalId:       "ext_123",
		Name:             "Test Resource",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	}
	resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_123",
		Name:             "Test Resource",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resource)
}

func TestAuthorizationCreateResourceWithParent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createResourceWithParentTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "resource_new",
		ExternalId:       "ext_123",
		Name:             "Test Resource",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		ParentResourceId: stringPtr("parent_123"),
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	}
	resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_123",
		Name:             "Test Resource",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		ParentResourceIdentifier: ParentResourceIdentifierById{ParentResourceId: "parent_123"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resource)
}

func TestAuthorizationGetResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getResourceWithoutParentHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "resource_123",
		ExternalId:       "ext_123",
		Name:             "Test Resource",
		Description:      stringPtr("A test resource"),
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	}
	resource, err := GetResource(context.Background(), GetAuthorizationResourceOpts{
		ResourceId: "resource_123",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resource)
}

func TestAuthorizationUpdateResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateResourceTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	newName := "Updated Resource"
	newDesc := "Updated description"
	expectedResponse := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "resource_123",
		ExternalId:       "ext_123",
		Name:             "Updated Resource",
		Description:      stringPtr("Updated description"),
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-02T00:00:00Z",
	}
	resource, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId:  "resource_123",
		Name:        &newName,
		Description: &newDesc,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resource)
}

func TestAuthorizationDeleteResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteResourceTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId: "resource_123",
	})

	require.NoError(t, err)
}

func TestAuthorizationListResources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listResourcesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{
			{
				Object:           "authorization_resource",
				Id:               "resource_001",
				ExternalId:       "ext_001",
				Name:             "Resource One",
				Description:      stringPtr("First resource"),
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: stringPtr("parent_001"),
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
			{
				Object:           "authorization_resource",
				Id:               "resource_002",
				ExternalId:       "ext_002",
				Name:             "Resource Two",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: nil,
				CreatedAt:        "2024-01-02T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "resource_002",
		},
	}
	resources, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resources)
}
