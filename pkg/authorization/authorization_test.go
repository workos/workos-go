package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

// setupDefaultClient configures the DefaultClient to point at the given test server.
func setupDefaultClient(server *httptest.Server) {
	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")
}

// ---------------------------------------------------------------------------
// CreateOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationCreateOrganizationRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createOrganizationRoleTestHandler))
	defer server.Close()

	setupDefaultClient(server)

	role, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
		Name:           "Org Admin",
	})

	require.NoError(t, err)
	require.Equal(t, "role_01ABC", role.Id)
	require.Equal(t, "Org Admin", role.Name)
	require.Equal(t, "org-admin", role.Slug)
	require.Equal(t, "OrganizationRole", role.Type)
}

// ---------------------------------------------------------------------------
// ListOrganizationRoles (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationListOrganizationRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listOrganizationRolesTestHandler))
	defer server.Close()

	setupDefaultClient(server)

	resp, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})

	require.NoError(t, err)
	require.Len(t, resp.Data, 2)
	require.Equal(t, "org-admin", resp.Data[0].Slug)
	require.Equal(t, "org-viewer", resp.Data[1].Slug)
}

// ---------------------------------------------------------------------------
// GetOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationGetOrganizationRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getOrganizationRoleTestHandler))
	defer server.Close()

	setupDefaultClient(server)

	role, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
	})

	require.NoError(t, err)
	require.Equal(t, "role_01ABC", role.Id)
	require.Equal(t, "Admin", role.Name)
	require.Equal(t, "org-admin", role.Slug)
}

// ---------------------------------------------------------------------------
// UpdateOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationUpdateOrganizationRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateOrganizationRoleTestHandler))
	defer server.Close()

	setupDefaultClient(server)

	name := "Super Admin"
	role, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
		Name:           &name,
	})

	require.NoError(t, err)
	require.Equal(t, "Super Admin", role.Name)
	require.Equal(t, "2024-01-02T00:00:00Z", role.UpdatedAt)
}

// ---------------------------------------------------------------------------
// DeleteOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationDeleteOrganizationRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteOrganizationRoleTestHandler))
	defer server.Close()

	setupDefaultClient(server)

	err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
	})

	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Stub wrapper tests -- verify package-level functions delegate correctly
// Each returns "not implemented" because the underlying Client method is a stub.
// ---------------------------------------------------------------------------

func TestAuthorizationCreateEnvironmentRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "admin",
		Name: "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListEnvironmentRoles(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetEnvironmentRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateEnvironmentRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationSetEnvironmentRolePermissions(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddEnvironmentRolePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationSetOrganizationRolePermissions(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		Permissions:    []string{"read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddOrganizationRolePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveOrganizationRolePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCreatePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "read",
		Name: "Read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListPermissions(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := ListPermissions(context.Background(), ListPermissionsOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetPermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := GetPermission(context.Background(), GetPermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdatePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := UpdatePermission(context.Background(), UpdatePermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeletePermission(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := DeletePermission(context.Background(), DeletePermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetResource(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCreateResource(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_01",
		Name:             "Test",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateResource(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteResource(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListResources(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCheck(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "read",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListRoleAssignments(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAssignRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRole(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleAssignmentId:         "ra_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListResourcesForMembership(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListMembershipsForResource(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "res_01ABC",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListMembershipsForResourceByExternalId(t *testing.T) {
	DefaultClient = &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
		PermissionSlug:   "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ---------------------------------------------------------------------------
// SetAPIKey
// ---------------------------------------------------------------------------

func TestSetAPIKey(t *testing.T) {
	DefaultClient = &Client{Endpoint: "https://api.workos.com"}
	SetAPIKey("my-api-key")
	require.Equal(t, "my-api-key", DefaultClient.APIKey)
}
