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

// Helper to set up a DefaultClient backed by a test server.
func setupDefaultClient(handler http.HandlerFunc) *httptest.Server {
	server := httptest.NewServer(handler)
	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")
	return server
}

// --- Environment Roles (stubs) ---

func TestAuthorizationCreateEnvironmentRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "admin",
		Name: "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListEnvironmentRoles(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetEnvironmentRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateEnvironmentRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	name := "Updated"
	_, err := UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug: "admin",
		Name: &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationSetEnvironmentRolePermissions(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"users:read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddEnvironmentRolePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "billing:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// --- Organization Roles (stubs) ---

func TestAuthorizationCreateOrganizationRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
		Name:           "Org Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListOrganizationRoles(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetOrganizationRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateOrganizationRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	name := "Updated Org Admin"
	_, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
		Name:           &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteOrganizationRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationSetOrganizationRolePermissions(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
		Permissions:    []string{"org:read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddOrganizationRolePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
		PermissionSlug: "billing:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveOrganizationRolePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	err := RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
		PermissionSlug: "billing:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// --- Permissions (stubs) ---

func TestAuthorizationCreatePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "users:read",
		Name: "Read Users",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListPermissions(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := ListPermissions(context.Background(), ListPermissionsOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetPermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := GetPermission(context.Background(), GetPermissionOpts{Slug: "users:read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdatePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	name := "Updated"
	_, err := UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "users:read",
		Name: &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeletePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	err := DeletePermission(context.Background(), DeletePermissionOpts{Slug: "users:read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// --- Resources (implemented) ---

func TestAuthorizationCreateResource(t *testing.T) {
	server := setupDefaultClient(http.HandlerFunc(createResourceWithoutParentTestHandler))
	defer server.Close()

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
	parentId := "parent_123"
	server := setupDefaultClient(http.HandlerFunc(createResourceWithParentTestHandler))
	defer server.Close()

	expectedResponse := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "resource_new",
		ExternalId:       "ext_123",
		Name:             "Test Resource",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		ParentResourceId: &parentId,
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	}
	resource, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:               "ext_123",
		Name:                     "Test Resource",
		ResourceTypeSlug:         "document",
		OrganizationId:           "org_123",
		ParentResourceIdentifier: ParentResourceIdentifierById{ParentResourceId: "parent_123"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resource)
}

func TestAuthorizationGetResource(t *testing.T) {
	testDesc := "A test resource"
	server := setupDefaultClient(http.HandlerFunc(getResourceWithoutParentHandler))
	defer server.Close()

	expectedResponse := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "resource_123",
		ExternalId:       "ext_123",
		Name:             "Test Resource",
		Description:      &testDesc,
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
	updatedDesc := "Updated description"
	server := setupDefaultClient(http.HandlerFunc(updateResourceTestHandler))
	defer server.Close()

	newName := "Updated Resource"
	newDesc := "Updated description"
	expectedResponse := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "resource_123",
		ExternalId:       "ext_123",
		Name:             "Updated Resource",
		Description:      &updatedDesc,
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
	server := setupDefaultClient(http.HandlerFunc(deleteResourceTestHandler))
	defer server.Close()

	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId: "resource_123",
	})

	require.NoError(t, err)
}

func TestAuthorizationListResources(t *testing.T) {
	firstDesc := "First resource"
	parentId := "parent_001"
	server := setupDefaultClient(http.HandlerFunc(listResourcesTestHandler))
	defer server.Close()

	expectedResponse := ListAuthorizationResourcesResponse{
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
	resources, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resources)
}

// --- Resources by External Id (stubs) ---

func TestAuthorizationGetResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	name := "Updated"
	_, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
		Name:             &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	err := DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// --- Access Check (stub) ---

func TestAuthorizationCheck(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_123",
		PermissionSlug:           "users:read",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// --- Role Assignments (stubs) ---

func TestAuthorizationListRoleAssignments(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAssignRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_123",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_123",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_123",
		RoleAssignmentId:         "ra_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// --- Membership/Resource Queries (stubs) ---

func TestAuthorizationListResourcesForMembership(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_123",
		PermissionSlug:           "users:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListMembershipsForResource(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "resource_123",
		PermissionSlug: "users:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListMembershipsForResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test"}

	_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_123",
		PermissionSlug:   "users:read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}
