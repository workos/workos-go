package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// withDefaultClient temporarily replaces DefaultClient for the duration of the
// test and restores the original value via t.Cleanup.
func withDefaultClient(t *testing.T, c *Client) {
	t.Helper()
	orig := DefaultClient
	DefaultClient = c
	t.Cleanup(func() { DefaultClient = orig })
}

// ---------------------------------------------------------------------------
// DefaultClient wrapper tests
//
// These verify that the package-level functions correctly delegate to
// DefaultClient, mirroring the pattern used in pkg/fga/fga_test.go.
// ---------------------------------------------------------------------------

func TestAuthorizationSetAPIKey(t *testing.T) {
	withDefaultClient(t, &Client{})
	SetAPIKey("my_key")
	require.Equal(t, "my_key", DefaultClient.APIKey)
}

// ---------------------------------------------------------------------------
// Environment Role Permission wrappers (implemented)
// ---------------------------------------------------------------------------

func TestAuthorizationSetEnvironmentRolePermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(setEnvironmentRolePermissionsHandler))
	defer server.Close()

	withDefaultClient(t, &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	})
	SetAPIKey("test")

	expectedResponse := EnvironmentRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "admin",
		Description: "Administrator role",
		Permissions: []string{"read:users", "write:users"},
		Type:        "EnvironmentRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	}

	role, err := SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		RoleSlug:    "admin",
		Permissions: []string{"read:users", "write:users"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, role)
}

func TestAuthorizationAddEnvironmentRolePermission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(addEnvironmentRolePermissionHandler))
	defer server.Close()

	withDefaultClient(t, &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	})
	SetAPIKey("test")

	expectedResponse := EnvironmentRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "admin",
		Description: "Administrator role",
		Permissions: []string{"read:users", "write:users", "delete:users"},
		Type:        "EnvironmentRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	}

	role, err := AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		RoleSlug:       "admin",
		PermissionSlug: "delete:users",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, role)
}

// ---------------------------------------------------------------------------
// Organization Role Permission wrappers (implemented)
// ---------------------------------------------------------------------------

func TestAuthorizationSetOrganizationRolePermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(setOrganizationRolePermissionsHandler))
	defer server.Close()

	withDefaultClient(t, &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	})
	SetAPIKey("test")

	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_02DEF",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Description: "Organization admin role",
		Permissions: []string{"manage:billing", "manage:members"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-02-01T00:00:00Z",
		UpdatedAt:   "2024-02-02T00:00:00Z",
	}

	role, err := SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_123",
		RoleSlug:       "org-admin",
		Permissions:    []string{"manage:billing", "manage:members"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, role)
}

func TestAuthorizationAddOrganizationRolePermission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(addOrganizationRolePermissionHandler))
	defer server.Close()

	withDefaultClient(t, &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	})
	SetAPIKey("test")

	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_02DEF",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Description: "Organization admin role",
		Permissions: []string{"manage:billing", "manage:members", "manage:settings"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-02-01T00:00:00Z",
		UpdatedAt:   "2024-02-02T00:00:00Z",
	}

	role, err := AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		RoleSlug:       "org-admin",
		PermissionSlug: "manage:settings",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, role)
}

func TestAuthorizationRemoveOrganizationRolePermission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(removeOrganizationRolePermissionHandler))
	defer server.Close()

	withDefaultClient(t, &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	})
	SetAPIKey("test")

	err := RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		RoleSlug:       "org-admin",
		PermissionSlug: "manage:settings",
	})

	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Stub wrapper tests (table-driven)
//
// All methods below are stubs returning "not implemented". This single test
// confirms the DefaultClient delegation path works and returns the expected
// error until the methods are fully implemented.
// ---------------------------------------------------------------------------

func TestStubMethodsDelegateToDefaultClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
	defer server.Close()

	withDefaultClient(t, &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	})
	SetAPIKey("test")

	name := "Updated"

	tests := []struct {
		name string
		fn   func() error
	}{
		{"CreateEnvironmentRole", func() error {
			_, err := CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{Slug: "admin", Name: "Admin"})
			return err
		}},
		{"ListEnvironmentRoles", func() error {
			_, err := ListEnvironmentRoles(context.Background())
			return err
		}},
		{"GetEnvironmentRole", func() error {
			_, err := GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{RoleSlug: "admin"})
			return err
		}},
		{"UpdateEnvironmentRole", func() error {
			_, err := UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{RoleSlug: "admin", Name: &name})
			return err
		}},
		{"CreateOrganizationRole", func() error {
			_, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{OrganizationId: "org_123", Slug: "admin", Name: "Admin"})
			return err
		}},
		{"ListOrganizationRoles", func() error {
			_, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{OrganizationId: "org_123"})
			return err
		}},
		{"GetOrganizationRole", func() error {
			_, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin"})
			return err
		}},
		{"UpdateOrganizationRole", func() error {
			_, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin", Name: &name})
			return err
		}},
		{"DeleteOrganizationRole", func() error {
			return DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin"})
		}},
		{"CreatePermission", func() error {
			_, err := CreatePermission(context.Background(), CreatePermissionOpts{Slug: "read:users", Name: "Read Users"})
			return err
		}},
		{"ListPermissions", func() error {
			_, err := ListPermissions(context.Background(), ListPermissionsOpts{})
			return err
		}},
		{"GetPermission", func() error {
			_, err := GetPermission(context.Background(), GetPermissionOpts{Slug: "read:users"})
			return err
		}},
		{"UpdatePermission", func() error {
			_, err := UpdatePermission(context.Background(), UpdatePermissionOpts{Slug: "read:users", Name: &name})
			return err
		}},
		{"DeletePermission", func() error {
			return DeletePermission(context.Background(), DeletePermissionOpts{Slug: "read:users"})
		}},
		{"GetResource", func() error {
			_, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_01ABC"})
			return err
		}},
		{"CreateResource", func() error {
			_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{ExternalId: "ext_123", Name: "My Resource", ResourceTypeSlug: "document", OrganizationId: "org_123"})
			return err
		}},
		{"UpdateResource", func() error {
			_, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{ResourceId: "resource_01ABC", Name: &name})
			return err
		}},
		{"DeleteResource", func() error {
			return DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "resource_01ABC"})
		}},
		{"ListResources", func() error {
			_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{OrganizationId: "org_123"})
			return err
		}},
		{"GetResourceByExternalId", func() error {
			_, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{OrganizationId: "org_123", ResourceTypeSlug: "document", ExternalId: "ext_456"})
			return err
		}},
		{"UpdateResourceByExternalId", func() error {
			_, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{OrganizationId: "org_123", ResourceTypeSlug: "document", ExternalId: "ext_456", Name: &name})
			return err
		}},
		{"DeleteResourceByExternalId", func() error {
			return DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{OrganizationId: "org_123", ResourceTypeSlug: "document", ExternalId: "ext_456"})
		}},
		{"Check", func() error {
			_, err := Check(context.Background(), AuthorizationCheckOpts{OrganizationMembershipId: "om_01ABC", PermissionSlug: "read:docs", ResourceIdentifier: ResourceIdentifierById{ResourceId: "resource_01ABC"}})
			return err
		}},
		{"ListRoleAssignments", func() error {
			_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{OrganizationMembershipId: "om_01ABC"})
			return err
		}},
		{"AssignRole", func() error {
			_, err := AssignRole(context.Background(), AssignRoleOpts{OrganizationMembershipId: "om_01ABC", RoleSlug: "admin", ResourceIdentifier: ResourceIdentifierById{ResourceId: "resource_01ABC"}})
			return err
		}},
		{"RemoveRole", func() error {
			return RemoveRole(context.Background(), RemoveRoleOpts{OrganizationMembershipId: "om_01ABC", RoleSlug: "admin", ResourceIdentifier: ResourceIdentifierById{ResourceId: "resource_01ABC"}})
		}},
		{"RemoveRoleAssignment", func() error {
			return RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{OrganizationMembershipId: "om_01ABC", RoleAssignmentId: "ra_01XYZ"})
		}},
		{"ListResourcesForMembership", func() error {
			_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{OrganizationMembershipId: "om_01ABC", PermissionSlug: "read:docs"})
			return err
		}},
		{"ListMembershipsForResource", func() error {
			_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{ResourceId: "resource_01ABC", PermissionSlug: "read:docs"})
			return err
		}},
		{"ListMembershipsForResourceByExternalId", func() error {
			_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{OrganizationId: "org_123", ResourceTypeSlug: "document", ExternalId: "ext_456", PermissionSlug: "read:docs"})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			require.Error(t, err)
			require.Contains(t, err.Error(), "not implemented")
		})
	}
}

// ---------------------------------------------------------------------------
// JSON Serialization Tests
// ---------------------------------------------------------------------------

func TestEnvironmentRole_JSONRoundTrip(t *testing.T) {
	role := EnvironmentRole{
		Object:           "role",
		Id:               "role_01ABC",
		Name:             "Admin",
		Slug:             "admin",
		Description:      "Administrator role",
		Permissions:      []string{"read:users", "write:users"},
		ResourceTypeSlug: "document",
		Type:             "EnvironmentRole",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-02T00:00:00Z",
	}

	data, err := json.Marshal(role)
	require.NoError(t, err)

	var decoded EnvironmentRole
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, role, decoded)
}

func TestOrganizationRole_JSONRoundTrip(t *testing.T) {
	role := OrganizationRole{
		Object:           "role",
		Id:               "role_02DEF",
		Name:             "Org Admin",
		Slug:             "org-admin",
		Description:      "Organization admin role",
		Permissions:      []string{"manage:billing"},
		ResourceTypeSlug: "workspace",
		Type:             "OrganizationRole",
		CreatedAt:        "2024-02-01T00:00:00Z",
		UpdatedAt:        "2024-02-02T00:00:00Z",
	}

	data, err := json.Marshal(role)
	require.NoError(t, err)

	var decoded OrganizationRole
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, role, decoded)
}

func TestPermission_JSONRoundTrip(t *testing.T) {
	perm := Permission{
		Object:           "permission",
		Id:               "perm_01ABC",
		Slug:             "read:users",
		Name:             "Read Users",
		Description:      "Can read users",
		ResourceTypeSlug: "user",
		System:           true,
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-02T00:00:00Z",
	}

	data, err := json.Marshal(perm)
	require.NoError(t, err)

	var decoded Permission
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, perm, decoded)
}

func TestAuthorizationResource_JSONRoundTrip(t *testing.T) {
	resource := AuthorizationResource{
		Object:           "resource",
		Id:               "resource_01ABC",
		ExternalId:       "ext_123",
		Name:             "My Document",
		Description:      "A document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		ParentResourceId: "parent_01ABC",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-02T00:00:00Z",
	}

	data, err := json.Marshal(resource)
	require.NoError(t, err)

	var decoded AuthorizationResource
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, resource, decoded)
}

func TestRoleAssignment_JSONRoundTrip(t *testing.T) {
	assignment := RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_01ABC",
		Role:   RoleAssignmentRole{Slug: "admin"},
		Resource: RoleAssignmentResource{
			Id:               "resource_01ABC",
			ExternalId:       "ext_123",
			ResourceTypeSlug: "document",
		},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	}

	data, err := json.Marshal(assignment)
	require.NoError(t, err)

	var decoded RoleAssignment
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, assignment, decoded)
}

func TestAccessCheckResponse_JSONRoundTrip(t *testing.T) {
	result := AccessCheckResponse{Authorized: true}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded AccessCheckResponse
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, result, decoded)
	require.True(t, decoded.Authorized)
}

func TestAuthorizationOrganizationMembership_JSONRoundTrip(t *testing.T) {
	membership := AuthorizationOrganizationMembership{
		Object:           "organization_membership",
		Id:               "om_01ABC",
		UserId:           "user_01XYZ",
		OrganizationId:   "org_123",
		Status:           "active",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-02T00:00:00Z",
		CustomAttributes: map[string]interface{}{"department": "engineering"},
	}

	data, err := json.Marshal(membership)
	require.NoError(t, err)

	var decoded AuthorizationOrganizationMembership
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, membership.Id, decoded.Id)
	require.Equal(t, membership.UserId, decoded.UserId)
	require.Equal(t, "engineering", decoded.CustomAttributes["department"])
}
