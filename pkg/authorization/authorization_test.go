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

// setupDefaultClient replaces the global DefaultClient with one pointing at
// the given test server. It returns a cleanup function that restores the
// original DefaultClient.
func setupDefaultClient(server *httptest.Server) func() {
	original := DefaultClient
	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")
	return func() {
		DefaultClient = original
	}
}

func TestAuthorizationCreateResource(t *testing.T) {
	parentId := "parent_123"

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, createdResourceWithParent))
		defer server.Close()

		original := DefaultClient
		DefaultClient = &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		defer func() { DefaultClient = original }()

		_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
		})
		require.Error(t, err)
	})

	t.Run("Creates resource with parent by ID", func(t *testing.T) {
		var capturedPath, capturedMethod string
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(&capturedPath, nil, &capturedMethod, &capturedBody, http.StatusOK, createdResourceWithParent))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:               "ext_123",
			Name:                     "Test Resource",
			ResourceTypeSlug:         "document",
			OrganizationId:           "org_123",
			ParentResourceIdentifier: ParentResourceIdentifierById{ParentResourceId: "parent_123"},
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources", capturedPath)
		require.Equal(t, http.MethodPost, capturedMethod)
		require.Equal(t, "parent_123", capturedBody["parent_resource_id"])
		require.Equal(t, AuthorizationResource{
			Object:           "authorization_resource",
			Id:               "resource_new",
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
			ParentResourceId: &parentId,
			CreatedAt:        "2024-01-01T00:00:00Z",
			UpdatedAt:        "2024-01-01T00:00:00Z",
		}, resource)
	})

	t.Run("Creates resource with parent by external ID", func(t *testing.T) {
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, createdResourceWithParent))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
			ParentResourceIdentifier: ParentResourceIdentifierByExternalId{
				ParentResourceExternalId: "parent_ext_123",
				ParentResourceTypeSlug:   "folder",
			},
		})

		require.NoError(t, err)
		require.Equal(t, "parent_ext_123", capturedBody["parent_resource_external_id"])
		require.Equal(t, "folder", capturedBody["parent_resource_type_slug"])
		require.NotContains(t, capturedBody, "parent_resource_id")
		require.Equal(t, createdResourceWithParent, resource)
	})

	t.Run("Creates resource without parent", func(t *testing.T) {
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, createdResourceWithoutParent))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
		})

		require.NoError(t, err)
		require.NotContains(t, capturedBody, "parent_resource_id")
		require.NotContains(t, capturedBody, "parent_resource_external_id")
		require.Equal(t, createdResourceWithoutParent, resource)
	})

	t.Run("Sends description when provided", func(t *testing.T) {
		var capturedBody map[string]interface{}
		expectedResource := resourceResponse("resource_new", "ext_123", "Test Resource", ptr("A resource"), nil, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, expectedResource))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			Description:      ptr("A resource"),
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
		})

		require.NoError(t, err)
		require.Equal(t, "A resource", capturedBody["description"])
		require.Equal(t, expectedResource, resource)
	})

	t.Run("Omits description when nil", func(t *testing.T) {
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, createdResourceWithoutParent))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
		})

		require.NoError(t, err)
		require.NotContains(t, capturedBody, "description")
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
		})
		require.Error(t, err)
	})

	t.Run("Sends correct request body fields", func(t *testing.T) {
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, createdResourceWithoutParent))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
		})

		require.NoError(t, err)
		require.Equal(t, "ext_123", capturedBody["external_id"])
		require.Equal(t, "Test Resource", capturedBody["name"])
		require.Equal(t, "document", capturedBody["resource_type_slug"])
		require.Equal(t, "org_123", capturedBody["organization_id"])
	})
}

func TestAuthorizationGetResource(t *testing.T) {
	testDesc := "A test resource"
	parentId := "parent_123"

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceAllFields))
		defer server.Close()

		original := DefaultClient
		DefaultClient = &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		defer func() { DefaultClient = original }()

		_, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})
		require.Error(t, err)
	})

	t.Run("Returns resource with all fields", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := httptest.NewServer(captureHandler(&capturedPath, nil, &capturedMethod, nil, http.StatusOK, existingResourceAllFields))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources/resource_123", capturedPath)
		require.Equal(t, http.MethodGet, capturedMethod)
		require.Equal(t, AuthorizationResource{
			Object:           "authorization_resource",
			Id:               "resource_123",
			ExternalId:       "ext_123",
			Name:             "Test Resource",
			Description:      &testDesc,
			ResourceTypeSlug: "document",
			OrganizationId:   "org_123",
			ParentResourceId: &parentId,
			CreatedAt:        "2024-01-01T00:00:00Z",
			UpdatedAt:        "2024-01-01T00:00:00Z",
		}, resource)
	})

	t.Run("Returns resource without parent", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceNoParent))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

		require.NoError(t, err)
		require.Nil(t, resource.ParentResourceId)
		require.Equal(t, &testDesc, resource.Description)
	})

	t.Run("Returns resource without description", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceNoDesc))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

		require.NoError(t, err)
		require.Nil(t, resource.Description)
		require.Equal(t, &parentId, resource.ParentResourceId)
	})

	t.Run("Returns resource without parent and description", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceMinimal))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

		require.NoError(t, err)
		require.Nil(t, resource.Description)
		require.Nil(t, resource.ParentResourceId)
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "nonexistent"})
		require.Error(t, err)
	})
}

func TestAuthorizationUpdateResource(t *testing.T) {
	newName := "Updated Resource"
	newDesc := "Updated description"

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, updatedResourceFull))
		defer server.Close()

		original := DefaultClient
		DefaultClient = &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		defer func() { DefaultClient = original }()

		_, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})
		require.Error(t, err)
	})

	t.Run("Updates name and description", func(t *testing.T) {
		var capturedPath, capturedMethod string
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(&capturedPath, nil, &capturedMethod, &capturedBody, http.StatusOK, updatedResourceFull))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId:  "resource_123",
			Name:        &newName,
			Description: &newDesc,
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources/resource_123", capturedPath)
		require.Equal(t, http.MethodPatch, capturedMethod)
		require.Equal(t, "Updated Resource", capturedBody["name"])
		require.Equal(t, "Updated description", capturedBody["description"])
		require.Equal(t, updatedResourceFull, resource)
	})

	t.Run("Updates name only", func(t *testing.T) {
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, updatedResourceNameOnly))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})

		require.NoError(t, err)
		require.Equal(t, "Updated Resource", capturedBody["name"])
		require.NotContains(t, capturedBody, "description")
		require.Equal(t, updatedResourceNameOnly, resource)
	})

	t.Run("Updates description only", func(t *testing.T) {
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, updatedResourceDescOnly))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId:  "resource_123",
			Description: &newDesc,
		})

		require.NoError(t, err)
		require.NotContains(t, capturedBody, "name")
		require.Equal(t, "Updated description", capturedBody["description"])
		require.Equal(t, updatedResourceDescOnly, resource)
	})

	t.Run("Sets description to null", func(t *testing.T) {
		var capturedBody map[string]interface{}
		server := httptest.NewServer(captureHandler(nil, nil, nil, &capturedBody, http.StatusOK, updatedResourceNullDesc))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resource, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})

		require.NoError(t, err)
		require.Equal(t, "Updated Resource", capturedBody["name"])
		require.NotContains(t, capturedBody, "description")
		require.Equal(t, updatedResourceNullDesc, resource)
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})
		require.Error(t, err)
	})
}

func TestAuthorizationDeleteResource(t *testing.T) {
	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusNoContent, nil))
		defer server.Close()

		original := DefaultClient
		DefaultClient = &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		defer func() { DefaultClient = original }()

		err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "resource_123"})
		require.Error(t, err)
	})

	t.Run("Deletes resource without cascade", func(t *testing.T) {
		var capturedPath, capturedQuery, capturedMethod string
		server := httptest.NewServer(captureHandler(&capturedPath, &capturedQuery, &capturedMethod, nil, http.StatusNoContent, nil))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
			ResourceId: "resource_123",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources/resource_123", capturedPath)
		require.Equal(t, http.MethodDelete, capturedMethod)
		require.NotContains(t, capturedQuery, "cascade_delete")
	})

	t.Run("Deletes resource with cascade true", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusNoContent, nil))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
			ResourceId:    "resource_123",
			CascadeDelete: boolPtr(true),
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "cascade_delete=true")
	})

	t.Run("Deletes resource with cascade false", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusNoContent, nil))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
			ResourceId:    "resource_123",
			CascadeDelete: boolPtr(false),
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "cascade_delete=false")
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "resource_123"})
		require.Error(t, err)
	})
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

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, listResponse))
		defer server.Close()

		original := DefaultClient
		DefaultClient = &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		defer func() { DefaultClient = original }()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})
		require.Error(t, err)
	})

	t.Run("Returns paginated resources", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := httptest.NewServer(captureHandler(&capturedPath, nil, &capturedMethod, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resources, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources", capturedPath)
		require.Equal(t, http.MethodGet, capturedMethod)
		require.Equal(t, listResponse, resources)
	})

	t.Run("Applies default limit of 10", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "limit=10")
	})

	t.Run("Passes custom limit", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{Limit: 5})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "limit=5")
	})

	t.Run("Filters by organization and resource type", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "organization_id=org_123")
		require.Contains(t, capturedQuery, "resource_type_slug=document")
	})

	t.Run("Paginates forward with after cursor", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
			Limit: 5,
			After: "resource_001",
			Order: common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "limit=5")
		require.Contains(t, capturedQuery, "after=resource_001")
		require.Contains(t, capturedQuery, "order=desc")
	})

	t.Run("Paginates backward with before cursor", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
			Limit:  5,
			Before: "resource_002",
			Order:  common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "limit=5")
		require.Contains(t, capturedQuery, "before=resource_002")
		require.Contains(t, capturedQuery, "order=asc")
	})

	t.Run("Filters by parent resource id", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
			ParentResourceId: "parent_001",
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "parent_resource_id=parent_001")
	})

	t.Run("Filters by parent external id and type slug", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
			ParentResourceTypeSlug: "folder",
			ParentExternalId:       "folder-123",
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "parent_resource_type_slug=folder")
		require.Contains(t, capturedQuery, "parent_external_id=folder-123")
	})

	t.Run("Filters by search term", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
			Search: "Budget",
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "search=Budget")
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})
		require.Error(t, err)
	})
}
