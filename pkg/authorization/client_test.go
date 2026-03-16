package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

// ---- Test helpers ----

func authHandler(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func jsonResponse(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	data, _ := json.Marshal(body)
	w.Write(data)
}

func ptr(s string) *string { return &s }

func newTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

func resourceResponse(id, extId, name string, desc, parentId *string, createdAt, updatedAt string) AuthorizationResource {
	return AuthorizationResource{
		Object:           "authorization_resource",
		Id:               id,
		ExternalId:       extId,
		Name:             name,
		Description:      desc,
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		ParentResourceId: parentId,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}
}

// captureHandler returns an http.HandlerFunc that captures the request path,
// raw query, method, and JSON body, then responds with the given status and body.
func captureHandler(
	capturedPath *string,
	capturedQuery *string,
	capturedMethod *string,
	capturedBody *map[string]interface{},
	status int,
	responseBody interface{},
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authHandler(w, r) {
			return
		}
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}
		if capturedQuery != nil {
			*capturedQuery = r.URL.RawQuery
		}
		if capturedMethod != nil {
			*capturedMethod = r.Method
		}
		if capturedBody != nil {
			_ = json.NewDecoder(r.Body).Decode(capturedBody)
		}
		if responseBody != nil {
			jsonResponse(w, status, responseBody)
		} else {
			w.WriteHeader(status)
		}
	}
}

// ---- Pre-built resource fixtures ----

var (
	createdResourceWithParent    = resourceResponse("resource_new", "ext_123", "Test Resource", nil, ptr("parent_123"), "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	createdResourceWithoutParent = resourceResponse("resource_new", "ext_123", "Test Resource", nil, nil, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	existingResourceAllFields    = resourceResponse("resource_123", "ext_123", "Test Resource", ptr("A test resource"), ptr("parent_123"), "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	existingResourceNoParent     = resourceResponse("resource_123", "ext_123", "Test Resource", ptr("A test resource"), nil, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	existingResourceNoDesc       = resourceResponse("resource_123", "ext_123", "Test Resource", nil, ptr("parent_123"), "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	existingResourceMinimal      = resourceResponse("resource_123", "ext_123", "Test Resource", nil, nil, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	updatedResourceFull          = resourceResponse("resource_123", "ext_123", "Updated Resource", ptr("Updated description"), nil, "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
	updatedResourceNameOnly      = resourceResponse("resource_123", "ext_123", "Updated Resource", ptr("A test resource"), nil, "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
	updatedResourceDescOnly      = resourceResponse("resource_123", "ext_123", "Test Resource", ptr("Updated description"), nil, "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
	updatedResourceNullDesc      = resourceResponse("resource_123", "ext_123", "Updated Resource", nil, nil, "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
)

// ===========================================================================
// Environment Roles (stubs)
// ===========================================================================

func TestCreateEnvironmentRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug:        "admin",
		Name:        "Admin",
		Description: "Full administrative access",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListEnvironmentRoles(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetEnvironmentRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateEnvironmentRole(t *testing.T) {
	name := "Super Admin"
	desc := "Updated description"
	client := &Client{APIKey: "test"}
	_, err := client.UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug: "admin", Name: &name, Description: &desc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestSetEnvironmentRolePermissions(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug: "admin", Permissions: []string{"users:read", "users:write"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddEnvironmentRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug: "admin", PermissionSlug: "billing:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ===========================================================================
// Organization Roles (stubs)
// ===========================================================================

func TestCreateOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
		Name:           "Org Admin",
		Description:    "Organization administrator",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListOrganizationRoles(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_123", Slug: "org-admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateOrganizationRole(t *testing.T) {
	name := "Super Org Admin"
	desc := "Updated description"
	client := &Client{APIKey: "test"}
	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_123", Slug: "org-admin", Name: &name, Description: &desc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_123", Slug: "org-admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestSetOrganizationRolePermissions(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_123", Slug: "org-admin", Permissions: []string{"org:read", "org:write"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddOrganizationRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_123", Slug: "org-admin", PermissionSlug: "billing:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveOrganizationRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_123", Slug: "org-admin", PermissionSlug: "billing:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ===========================================================================
// Permissions (stubs)
// ===========================================================================

func TestCreatePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
		Slug:        "users:read",
		Name:        "Read Users",
		Description: "Allows reading user data",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListPermissions(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetPermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetPermission(context.Background(), GetPermissionOpts{Slug: "users:read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdatePermission(t *testing.T) {
	name := "Read All Users"
	desc := "Updated description"
	client := &Client{APIKey: "test"}
	_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "users:read", Name: &name, Description: &desc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeletePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.DeletePermission(context.Background(), DeletePermissionOpts{Slug: "users:read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ===========================================================================
// Resources (implemented)
// ===========================================================================

func TestCreateResource(t *testing.T) {
	parentId := "parent_123"

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, createdResourceWithParent))
		defer server.Close()

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

		client := newTestClient(server)
		resource, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

		client := newTestClient(server)
		resource, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

		client := newTestClient(server)
		resource, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

		client := newTestClient(server)
		resource, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

		client := newTestClient(server)
		_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

		client := newTestClient(server)
		_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

		client := newTestClient(server)
		_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
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

func TestGetResource(t *testing.T) {
	testDesc := "A test resource"
	parentId := "parent_123"

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceAllFields))
		defer server.Close()

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		_, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})
		require.Error(t, err)
	})

	t.Run("Returns resource with all fields", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := httptest.NewServer(captureHandler(&capturedPath, nil, &capturedMethod, nil, http.StatusOK, existingResourceAllFields))
		defer server.Close()

		client := newTestClient(server)
		resource, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

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

		client := newTestClient(server)
		resource, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

		require.NoError(t, err)
		require.Nil(t, resource.ParentResourceId)
		require.Equal(t, &testDesc, resource.Description)
	})

	t.Run("Returns resource without description", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceNoDesc))
		defer server.Close()

		client := newTestClient(server)
		resource, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

		require.NoError(t, err)
		require.Nil(t, resource.Description)
		require.Equal(t, &parentId, resource.ParentResourceId)
	})

	t.Run("Returns resource without parent and description", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, existingResourceMinimal))
		defer server.Close()

		client := newTestClient(server)
		resource, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_123"})

		require.NoError(t, err)
		require.Nil(t, resource.Description)
		require.Nil(t, resource.ParentResourceId)
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := newTestClient(server)
		_, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "nonexistent"})
		require.Error(t, err)
	})
}

func TestUpdateResource(t *testing.T) {
	newName := "Updated Resource"
	newDesc := "Updated description"

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, updatedResourceFull))
		defer server.Close()

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		_, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})
		require.Error(t, err)
	})

	t.Run("Updates name and description", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := httptest.NewServer(captureHandler(&capturedPath, nil, &capturedMethod, nil, http.StatusOK, updatedResourceFull))
		defer server.Close()

		client := newTestClient(server)
		resource, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId:  "resource_123",
			Name:        &newName,
			Description: &newDesc,
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources/resource_123", capturedPath)
		require.Equal(t, http.MethodPatch, capturedMethod)
		require.Equal(t, updatedResourceFull, resource)
	})

	t.Run("Updates name only", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, updatedResourceNameOnly))
		defer server.Close()

		client := newTestClient(server)
		resource, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})

		require.NoError(t, err)
		require.Equal(t, updatedResourceNameOnly, resource)
	})

	t.Run("Updates description only", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, updatedResourceDescOnly))
		defer server.Close()

		client := newTestClient(server)
		resource, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId:  "resource_123",
			Description: &newDesc,
		})

		require.NoError(t, err)
		require.Equal(t, updatedResourceDescOnly, resource)
	})

	t.Run("Sets description to null", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusOK, updatedResourceNullDesc))
		defer server.Close()

		client := newTestClient(server)
		resource, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})

		require.NoError(t, err)
		require.Equal(t, updatedResourceNullDesc, resource)
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newTestClient(server)
		_, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
			ResourceId: "resource_123",
			Name:       &newName,
		})
		require.Error(t, err)
	})
}

func TestDeleteResource(t *testing.T) {
	t.Run("Request without API Key returns an error", func(t *testing.T) {
		server := httptest.NewServer(captureHandler(nil, nil, nil, nil, http.StatusNoContent, nil))
		defer server.Close()

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "resource_123"})
		require.Error(t, err)
	})

	t.Run("Deletes resource without cascade", func(t *testing.T) {
		var capturedPath, capturedQuery, capturedMethod string
		server := httptest.NewServer(captureHandler(&capturedPath, &capturedQuery, &capturedMethod, nil, http.StatusNoContent, nil))
		defer server.Close()

		client := newTestClient(server)
		err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
			ResourceId: "resource_123",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources/resource_123", capturedPath)
		require.Equal(t, http.MethodDelete, capturedMethod)
		require.NotContains(t, capturedQuery, "cascade_delete")
	})

	t.Run("Deletes resource with cascade true sets query param", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusNoContent, nil))
		defer server.Close()

		client := newTestClient(server)
		err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
			ResourceId:    "resource_123",
			CascadeDelete: true,
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "cascade_delete=true")
	})

	t.Run("Deletes resource with cascade false omits query param", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusNoContent, nil))
		defer server.Close()

		client := newTestClient(server)
		err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
			ResourceId:    "resource_123",
			CascadeDelete: false,
		})

		require.NoError(t, err)
		require.NotContains(t, capturedQuery, "cascade_delete")
	})

	t.Run("Returns error when endpoint returns HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newTestClient(server)
		err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "resource_123"})
		require.Error(t, err)
	})
}

func TestListResources(t *testing.T) {
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

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{})
		require.Error(t, err)
	})

	t.Run("Returns paginated resources", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := httptest.NewServer(captureHandler(&capturedPath, nil, &capturedMethod, nil, http.StatusOK, listResponse))
		defer server.Close()

		client := newTestClient(server)
		resources, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{})

		require.NoError(t, err)
		require.Equal(t, "/authorization/resources", capturedPath)
		require.Equal(t, http.MethodGet, capturedMethod)
		require.Equal(t, listResponse, resources)
	})

	t.Run("Applies default limit of 10", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "limit=10")
	})

	t.Run("Passes custom limit", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{Limit: 5})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "limit=5")
	})

	t.Run("Filters by organization and resource type", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
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

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
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

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
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

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
			ParentResourceId: "parent_001",
		})

		require.NoError(t, err)
		require.Contains(t, capturedQuery, "parent_resource_id=parent_001")
	})

	t.Run("Filters by parent external id and type slug", func(t *testing.T) {
		var capturedQuery string
		server := httptest.NewServer(captureHandler(nil, &capturedQuery, nil, nil, http.StatusOK, listResponse))
		defer server.Close()

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
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

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
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

		client := newTestClient(server)
		_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{})
		require.Error(t, err)
	})
}

// ===========================================================================
// Resources by External Id (stubs)
// ===========================================================================

func TestGetResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateResourceByExternalId(t *testing.T) {
	name := "Updated"
	desc := "Updated description"
	client := &Client{APIKey: "test"}
	_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
		Name:             &name,
		Description:      &desc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ===========================================================================
// Access Check (stub)
// ===========================================================================

func TestCheck(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_123",
		PermissionSlug:           "users:read",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ===========================================================================
// Role Assignments (stubs)
// ===========================================================================

func TestListRoleAssignments(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAssignRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_123",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_123",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveRoleAssignment(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_123",
		RoleAssignmentId:         "ra_001",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ===========================================================================
// Membership/Resource Queries (stubs)
// ===========================================================================

func TestListResourcesForMembership(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_123",
		PermissionSlug:           "users:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResource(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "resource_123",
		PermissionSlug: "users:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
		PermissionSlug:   "users:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}


