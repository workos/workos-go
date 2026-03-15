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

// -----------------------------------------------------------------------
// Package-level functions delegate to DefaultClient.
// Implemented methods are tested via httptest; stub methods verify the
// "not implemented" error propagates correctly through the wrapper.
// -----------------------------------------------------------------------

func TestSetAPIKey(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("my_api_key")
	require.Equal(t, "my_api_key", DefaultClient.APIKey)
}

// -----------------------------------------------------------------------
// Permissions (implemented -- full round-trip via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationCreatePermission(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	server := httptest.NewServer(http.HandlerFunc(createPermissionTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	permission, err := CreatePermission(context.Background(), CreatePermissionOpts{
		Slug:             "documents.read",
		Name:             "Read Documents",
		Description:      "Allows reading documents",
		ResourceTypeSlug: "document",
	})
	require.NoError(t, err)
	require.Equal(t, "perm_01HXYZ", permission.Id)
	require.Equal(t, "documents.read", permission.Slug)
	require.Equal(t, "Read Documents", permission.Name)
	require.Equal(t, "Allows reading documents", permission.Description)
	require.Equal(t, "document", permission.ResourceTypeSlug)
}

func TestAuthorizationListPermissions(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	server := httptest.NewServer(http.HandlerFunc(listPermissionsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expected := listPermissionsExpectedResponse()
	permissions, err := ListPermissions(context.Background(), ListPermissionsOpts{})
	require.NoError(t, err)
	require.Equal(t, expected, permissions)
}

func TestAuthorizationGetPermission(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	server := httptest.NewServer(http.HandlerFunc(getPermissionTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	permission, err := GetPermission(context.Background(), GetPermissionOpts{
		Slug: "documents.read",
	})
	require.NoError(t, err)
	require.Equal(t, "perm_01HXYZ", permission.Id)
	require.Equal(t, "documents.read", permission.Slug)
}

func TestAuthorizationUpdatePermission(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	server := httptest.NewServer(http.HandlerFunc(updatePermissionTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	newName := "Read All Documents"
	permission, err := UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "documents.read",
		Name: &newName,
	})
	require.NoError(t, err)
	require.Equal(t, "Read All Documents", permission.Name)
}

func TestAuthorizationDeletePermission(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	server := httptest.NewServer(http.HandlerFunc(deletePermissionTestHandler))
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

// -----------------------------------------------------------------------
// Environment Roles (stubs via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationCreateEnvironmentRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "admin",
		Name: "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListEnvironmentRoles(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetEnvironmentRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateEnvironmentRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	newName := "Super Admin"
	_, err := UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug: "admin",
		Name: &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Organization Roles (stubs via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationCreateOrganizationRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Name:           "Editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListOrganizationRoles(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetOrganizationRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateOrganizationRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	newName := "Senior Editor"
	_, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Name:           &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteOrganizationRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Role Permissions (stubs via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationSetEnvironmentRolePermissions(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"documents.read", "documents.write"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddEnvironmentRolePermission(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationSetOrganizationRolePermissions(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Permissions:    []string{"documents.read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddOrganizationRolePermission(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		PermissionSlug: "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveOrganizationRolePermission(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	err := RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		PermissionSlug: "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Resources (stubs via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationGetResource(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := GetResource(context.Background(), GetAuthorizationResourceOpts{
		ResourceId: "res_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCreateResource(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_doc_123",
		Name:             "Test Document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateResource(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	newName := "Updated"
	_, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId: "res_01ABC",
		Name:       &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteResource(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId: "res_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListResources(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetResourceByExternalId(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateResourceByExternalId(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	newName := "Updated"
	_, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
		Name:             &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteResourceByExternalId(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	err := DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Authorization Check (stub via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationCheck(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "documents.read",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01XYZ"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Role Assignments (stubs via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationListRoleAssignments(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAssignRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "editor",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01XYZ"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRole(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "editor",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01XYZ"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleAssignmentId:         "ra_01XYZ",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Membership / Resource queries (stubs via DefaultClient)
// -----------------------------------------------------------------------

func TestAuthorizationListResourcesForMembership(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListMembershipsForResource(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "res_01XYZ",
		PermissionSlug: "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListMembershipsForResourceByExternalId(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("test")

	_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
		PermissionSlug:   "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// ListPermissions with pagination via DefaultClient
// -----------------------------------------------------------------------

func TestAuthorizationListPermissionsWithPagination(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	server := httptest.NewServer(http.HandlerFunc(listPermissionsPaginationTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	permissions, err := ListPermissions(context.Background(), ListPermissionsOpts{
		Limit: 5,
		After: "perm_01HXYZ",
		Order: common.Asc,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(permissions.Data))
	require.Equal(t, "perm_02HXYZ", permissions.Data[0].Id)
	require.Equal(t, "perm_01HXYZ", permissions.ListMetadata.Before)
}
