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

func TestAuthorizationListPermissionsWithPagination(t *testing.T) {
	orig := DefaultClient
	t.Cleanup(func() { DefaultClient = orig })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		q := r.URL.Query()
		if q.Get("limit") != "5" || q.Get("after") != "perm_01HXYZ" || q.Get("order") != "asc" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[{"object":"permission","id":"perm_02HXYZ","slug":"documents.write","name":"Write Documents","system":false,"created_at":"2024-01-02T00:00:00Z","updated_at":"2024-01-02T00:00:00Z"}],"list_metadata":{"before":"perm_01HXYZ","after":""}}`))
	}))
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

// -----------------------------------------------------------------------
// Stub methods (not yet implemented) -- verify "not implemented" error
// propagates correctly through the package-level wrapper functions.
// All stubs are consolidated into a single table-driven test.
// -----------------------------------------------------------------------

func TestAuthorizationStubMethodsDelegateNotImplementedError(t *testing.T) {
	newName := "Updated"

	tests := []struct {
		name    string
		callFn func(ctx context.Context) error
	}{
		// Environment Roles
		{
			name: "CreateEnvironmentRole",
			callFn: func(ctx context.Context) error {
				_, err := CreateEnvironmentRole(ctx, CreateEnvironmentRoleOpts{Slug: "admin", Name: "Admin"})
				return err
			},
		},
		{
			name: "ListEnvironmentRoles",
			callFn: func(ctx context.Context) error {
				_, err := ListEnvironmentRoles(ctx)
				return err
			},
		},
		{
			name: "GetEnvironmentRole",
			callFn: func(ctx context.Context) error {
				_, err := GetEnvironmentRole(ctx, GetEnvironmentRoleOpts{Slug: "admin"})
				return err
			},
		},
		{
			name: "UpdateEnvironmentRole",
			callFn: func(ctx context.Context) error {
				_, err := UpdateEnvironmentRole(ctx, UpdateEnvironmentRoleOpts{Slug: "admin", Name: &newName})
				return err
			},
		},

		// Organization Roles
		{
			name: "CreateOrganizationRole",
			callFn: func(ctx context.Context) error {
				_, err := CreateOrganizationRole(ctx, CreateOrganizationRoleOpts{OrganizationId: "org_01ABC", Slug: "editor", Name: "Editor"})
				return err
			},
		},
		{
			name: "ListOrganizationRoles",
			callFn: func(ctx context.Context) error {
				_, err := ListOrganizationRoles(ctx, ListOrganizationRolesOpts{OrganizationId: "org_01ABC"})
				return err
			},
		},
		{
			name: "GetOrganizationRole",
			callFn: func(ctx context.Context) error {
				_, err := GetOrganizationRole(ctx, GetOrganizationRoleOpts{OrganizationId: "org_01ABC", Slug: "editor"})
				return err
			},
		},
		{
			name: "UpdateOrganizationRole",
			callFn: func(ctx context.Context) error {
				_, err := UpdateOrganizationRole(ctx, UpdateOrganizationRoleOpts{OrganizationId: "org_01ABC", Slug: "editor", Name: &newName})
				return err
			},
		},
		{
			name: "DeleteOrganizationRole",
			callFn: func(ctx context.Context) error {
				return DeleteOrganizationRole(ctx, DeleteOrganizationRoleOpts{OrganizationId: "org_01ABC", Slug: "editor"})
			},
		},

		// Role Permissions
		{
			name: "SetEnvironmentRolePermissions",
			callFn: func(ctx context.Context) error {
				_, err := SetEnvironmentRolePermissions(ctx, SetEnvironmentRolePermissionsOpts{Slug: "admin", Permissions: []string{"documents.read", "documents.write"}})
				return err
			},
		},
		{
			name: "AddEnvironmentRolePermission",
			callFn: func(ctx context.Context) error {
				_, err := AddEnvironmentRolePermission(ctx, AddEnvironmentRolePermissionOpts{Slug: "admin", PermissionSlug: "documents.read"})
				return err
			},
		},
		{
			name: "SetOrganizationRolePermissions",
			callFn: func(ctx context.Context) error {
				_, err := SetOrganizationRolePermissions(ctx, SetOrganizationRolePermissionsOpts{OrganizationId: "org_01ABC", Slug: "editor", Permissions: []string{"documents.read"}})
				return err
			},
		},
		{
			name: "AddOrganizationRolePermission",
			callFn: func(ctx context.Context) error {
				_, err := AddOrganizationRolePermission(ctx, AddOrganizationRolePermissionOpts{OrganizationId: "org_01ABC", Slug: "editor", PermissionSlug: "documents.read"})
				return err
			},
		},
		{
			name: "RemoveOrganizationRolePermission",
			callFn: func(ctx context.Context) error {
				return RemoveOrganizationRolePermission(ctx, RemoveOrganizationRolePermissionOpts{OrganizationId: "org_01ABC", Slug: "editor", PermissionSlug: "documents.read"})
			},
		},

		// Resources
		{
			name: "GetResource",
			callFn: func(ctx context.Context) error {
				_, err := GetResource(ctx, GetAuthorizationResourceOpts{ResourceId: "res_01ABC"})
				return err
			},
		},
		{
			name: "CreateResource",
			callFn: func(ctx context.Context) error {
				_, err := CreateResource(ctx, CreateAuthorizationResourceOpts{ExternalId: "ext_doc_123", Name: "Test Document", ResourceTypeSlug: "document", OrganizationId: "org_01ABC"})
				return err
			},
		},
		{
			name: "UpdateResource",
			callFn: func(ctx context.Context) error {
				_, err := UpdateResource(ctx, UpdateAuthorizationResourceOpts{ResourceId: "res_01ABC", Name: &newName})
				return err
			},
		},
		{
			name: "DeleteResource",
			callFn: func(ctx context.Context) error {
				return DeleteResource(ctx, DeleteAuthorizationResourceOpts{ResourceId: "res_01ABC"})
			},
		},
		{
			name: "ListResources",
			callFn: func(ctx context.Context) error {
				_, err := ListResources(ctx, ListAuthorizationResourcesOpts{OrganizationId: "org_01ABC", ResourceTypeSlug: "document"})
				return err
			},
		},
		{
			name: "GetResourceByExternalId",
			callFn: func(ctx context.Context) error {
				_, err := GetResourceByExternalId(ctx, GetResourceByExternalIdOpts{OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "ext_doc_123"})
				return err
			},
		},
		{
			name: "UpdateResourceByExternalId",
			callFn: func(ctx context.Context) error {
				_, err := UpdateResourceByExternalId(ctx, UpdateResourceByExternalIdOpts{OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "ext_doc_123", Name: &newName})
				return err
			},
		},
		{
			name: "DeleteResourceByExternalId",
			callFn: func(ctx context.Context) error {
				return DeleteResourceByExternalId(ctx, DeleteResourceByExternalIdOpts{OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "ext_doc_123"})
			},
		},

		// Authorization Check
		{
			name: "Check",
			callFn: func(ctx context.Context) error {
				_, err := Check(ctx, AuthorizationCheckOpts{OrganizationMembershipId: "om_01ABC", PermissionSlug: "documents.read", Resource: ResourceIdentifierById{ResourceId: "res_01XYZ"}})
				return err
			},
		},

		// Role Assignments
		{
			name: "ListRoleAssignments",
			callFn: func(ctx context.Context) error {
				_, err := ListRoleAssignments(ctx, ListRoleAssignmentsOpts{OrganizationMembershipId: "om_01ABC"})
				return err
			},
		},
		{
			name: "AssignRole",
			callFn: func(ctx context.Context) error {
				_, err := AssignRole(ctx, AssignRoleOpts{OrganizationMembershipId: "om_01ABC", RoleSlug: "editor", Resource: ResourceIdentifierById{ResourceId: "res_01XYZ"}})
				return err
			},
		},
		{
			name: "RemoveRole",
			callFn: func(ctx context.Context) error {
				return RemoveRole(ctx, RemoveRoleOpts{OrganizationMembershipId: "om_01ABC", RoleSlug: "editor", Resource: ResourceIdentifierById{ResourceId: "res_01XYZ"}})
			},
		},
		{
			name: "RemoveRoleAssignment",
			callFn: func(ctx context.Context) error {
				return RemoveRoleAssignment(ctx, RemoveRoleAssignmentOpts{OrganizationMembershipId: "om_01ABC", RoleAssignmentId: "ra_01XYZ"})
			},
		},

		// Membership / Resource queries
		{
			name: "ListResourcesForMembership",
			callFn: func(ctx context.Context) error {
				_, err := ListResourcesForMembership(ctx, ListResourcesForMembershipOpts{OrganizationMembershipId: "om_01ABC", PermissionSlug: "documents.read"})
				return err
			},
		},
		{
			name: "ListMembershipsForResource",
			callFn: func(ctx context.Context) error {
				_, err := ListMembershipsForResource(ctx, ListMembershipsForResourceOpts{ResourceId: "res_01XYZ", PermissionSlug: "documents.read"})
				return err
			},
		},
		{
			name: "ListMembershipsForResourceByExternalId",
			callFn: func(ctx context.Context) error {
				_, err := ListMembershipsForResourceByExternalId(ctx, ListMembershipsForResourceByExternalIdOpts{OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "ext_doc_123", PermissionSlug: "documents.read"})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orig := DefaultClient
			t.Cleanup(func() { DefaultClient = orig })
			DefaultClient = &Client{Endpoint: "https://api.workos.com"}
			SetAPIKey("test")

			err := test.callFn(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), "not implemented")
		})
	}
}
