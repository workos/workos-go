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

func setupDefaultClient(server *httptest.Server) {
	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")
}

func TestAuthorizationCreateResource(t *testing.T) {
	server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, createdResourceWithParent))
	defer server.Close()

	setupDefaultClient(server)

	resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:               "ext_123",
		Name:                     "Test Resource",
		ResourceTypeSlug:         "document",
		OrganizationId:           "org_123",
		ParentResourceIdentifier: ParentResourceIdentifierById{ParentResourceId: "parent_123"},
	})

	require.NoError(t, err)
	require.Equal(t, createdResourceWithParent, resource)
}

func TestAuthorizationGetResource(t *testing.T) {
	server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceAllFields))
	defer server.Close()

	setupDefaultClient(server)

	resource, err := GetResource(context.Background(), GetAuthorizationResourceOpts{
		ResourceId: "resource_123",
	})

	require.NoError(t, err)
	require.Equal(t, existingResourceAllFields, resource)
}

func TestAuthorizationUpdateResource(t *testing.T) {
	server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, updatedResourceFull))
	defer server.Close()

	setupDefaultClient(server)

	newName := "Updated Resource"
	newDesc := "Updated description"
	resource, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId:  "resource_123",
		Name:        &newName,
		Description: &newDesc,
	})

	require.NoError(t, err)
	require.Equal(t, updatedResourceFull, resource)
}

func TestAuthorizationDeleteResource(t *testing.T) {
	server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusNoContent, nil))
	defer server.Close()

	setupDefaultClient(server)

	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId: "resource_123",
	})

	require.NoError(t, err)
}

func TestAuthorizationListResources(t *testing.T) {
	firstDesc := "First resource"
	parentId := "parent_001"

	listResponse := ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{
			{
				Object:           "authorization_resource",
				Id:               "resource_001",
				ExternalId:       "ext_001",
				Name:             "Resource One",
				Description:      &firstDesc,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: &parentId,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "resource_001",
		},
	}

	server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, listResponse))
	defer server.Close()

	setupDefaultClient(server)

	resources, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
	})

	require.NoError(t, err)
	require.Equal(t, listResponse, resources)
}
