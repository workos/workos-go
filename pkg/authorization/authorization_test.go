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

// mockAuthClient creates a test client wired to the given test server.
func mockAuthClient(s *httptest.Server) *Client {
	return &Client{
		Endpoint:   s.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *s.Client()},
	}
}

// --- DefaultClient wrapper tests ---
// These verify that every package-level function correctly delegates to DefaultClient.

func TestSetAPIKey(t *testing.T) {
	original := DefaultClient
	defer func() { DefaultClient = original }()

	DefaultClient = &Client{}
	SetAPIKey("test-key-123")
	require.Equal(t, "test-key-123", DefaultClient.APIKey)
}

func TestDefaultGetResourceByExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getResourceByExternalIdTestHandler))
	defer server.Close()

	original := DefaultClient
	defer func() { DefaultClient = original }()

	DefaultClient = mockAuthClient(server)
	SetAPIKey("test")

	resource, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		ResourceTypeSlug: "document",
		ExternalId:       "my-document-1",
	})
	require.NoError(t, err)
	require.Equal(t, "rsrc_01H945H0YD4F97JN3MNHBFPG37", resource.Id)
	require.Equal(t, "my-document-1", resource.ExternalId)
}

func TestDefaultUpdateResourceByExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateResourceByExternalIdTestHandler))
	defer server.Close()

	original := DefaultClient
	defer func() { DefaultClient = original }()

	DefaultClient = mockAuthClient(server)
	SetAPIKey("test")

	newName := "Updated Document"
	newDescription := "Updated description"
	resource, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		ResourceTypeSlug: "document",
		ExternalId:       "my-document-1",
		Name:             &newName,
		Description:      &newDescription,
	})
	require.NoError(t, err)
	require.Equal(t, "Updated Document", resource.Name)
}

func TestDefaultDeleteResourceByExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteResourceByExternalIdTestHandler))
	defer server.Close()

	original := DefaultClient
	defer func() { DefaultClient = original }()

	DefaultClient = mockAuthClient(server)
	SetAPIKey("test")

	err := DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		ResourceTypeSlug: "document",
		ExternalId:       "my-document-1",
	})
	require.NoError(t, err)
}

// --- Stub method delegation tests ---
// These verify that package-level wrappers for not-yet-implemented methods
// correctly delegate and return the expected "not implemented" error.

func TestDefaultCreateEnvironmentRole(t *testing.T) {
	_, err := CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "admin",
		Name: "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListEnvironmentRoles(t *testing.T) {
	_, err := ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultGetEnvironmentRole(t *testing.T) {
	_, err := GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultUpdateEnvironmentRole(t *testing.T) {
	_, err := UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultCreateOrganizationRole(t *testing.T) {
	_, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
		Name:           "Editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListOrganizationRoles(t *testing.T) {
	_, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultGetOrganizationRole(t *testing.T) {
	_, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultUpdateOrganizationRole(t *testing.T) {
	_, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultDeleteOrganizationRole(t *testing.T) {
	err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultSetEnvironmentRolePermissions(t *testing.T) {
	_, err := SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read", "write"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultAddEnvironmentRolePermission(t *testing.T) {
	_, err := AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "delete",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultSetOrganizationRolePermissions(t *testing.T) {
	_, err := SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
		Permissions:    []string{"read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultAddOrganizationRolePermission(t *testing.T) {
	_, err := AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
		PermissionSlug: "write",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultRemoveOrganizationRolePermission(t *testing.T) {
	err := RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
		PermissionSlug: "write",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultCreatePermission(t *testing.T) {
	_, err := CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "read",
		Name: "Read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListPermissions(t *testing.T) {
	_, err := ListPermissions(context.Background(), ListPermissionsOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultGetPermission(t *testing.T) {
	_, err := GetPermission(context.Background(), GetPermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultUpdatePermission(t *testing.T) {
	_, err := UpdatePermission(context.Background(), UpdatePermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultDeletePermission(t *testing.T) {
	err := DeletePermission(context.Background(), DeletePermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultGetResource(t *testing.T) {
	_, err := GetResource(context.Background(), GetAuthorizationResourceOpts{
		ResourceId: "rsrc_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultCreateResource(t *testing.T) {
	_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext-1",
		Name:             "Test",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultUpdateResource(t *testing.T) {
	_, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId: "rsrc_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultDeleteResource(t *testing.T) {
	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId: "rsrc_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListResources(t *testing.T) {
	_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultCheck(t *testing.T) {
	_, err := Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_123",
		PermissionSlug:           "read",
		Resource:                 ResourceIdentifierById{ResourceId: "rsrc_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListRoleAssignments(t *testing.T) {
	_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultAssignRole(t *testing.T) {
	_, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_123",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "rsrc_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultRemoveRole(t *testing.T) {
	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_123",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "rsrc_123"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultRemoveRoleAssignment(t *testing.T) {
	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_123",
		RoleAssignmentId:         "ra_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListResourcesForMembership(t *testing.T) {
	_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_123",
		PermissionSlug:           "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListMembershipsForResource(t *testing.T) {
	_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "rsrc_123",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDefaultListMembershipsForResourceByExternalId(t *testing.T) {
	_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		PermissionSlug:   "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// --- JSON serialization tests ---

func TestEnvironmentRoleJSONRoundTrip(t *testing.T) {
	role := EnvironmentRole{
		Object:           "authorization_role",
		Id:               "role_123",
		Name:             "Admin",
		Slug:             "admin",
		Description:      "Full access",
		Permissions:      []string{"read", "write", "delete"},
		ResourceTypeSlug: "document",
		Type:             "environment",
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-01T00:00:00.000Z",
	}

	data, err := json.Marshal(role)
	require.NoError(t, err)

	var decoded EnvironmentRole
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, role, decoded)
}

func TestOrganizationRoleJSONRoundTrip(t *testing.T) {
	role := OrganizationRole{
		Object:           "authorization_role",
		Id:               "role_456",
		Name:             "Editor",
		Slug:             "editor",
		Description:      "Can edit",
		Permissions:      []string{"read", "write"},
		ResourceTypeSlug: "document",
		Type:             "organization",
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-01T00:00:00.000Z",
	}

	data, err := json.Marshal(role)
	require.NoError(t, err)

	var decoded OrganizationRole
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, role, decoded)
}

func TestPermissionJSONRoundTrip(t *testing.T) {
	perm := Permission{
		Object:           "authorization_permission",
		Id:               "perm_123",
		Slug:             "read",
		Name:             "Read",
		Description:      "Read access",
		ResourceTypeSlug: "document",
		System:           false,
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-01T00:00:00.000Z",
	}

	data, err := json.Marshal(perm)
	require.NoError(t, err)

	var decoded Permission
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, perm, decoded)
}

func TestAuthorizationResourceJSONRoundTrip(t *testing.T) {
	resource := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "rsrc_123",
		ExternalId:       "ext-1",
		Name:             "My Document",
		Description:      "A test document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
		ParentResourceId: "rsrc_parent",
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-01T00:00:00.000Z",
	}

	data, err := json.Marshal(resource)
	require.NoError(t, err)

	var decoded AuthorizationResource
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, resource, decoded)
}

func TestRoleAssignmentJSONRoundTrip(t *testing.T) {
	assignment := RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_123",
		Role:   RoleAssignmentRole{Slug: "admin"},
		Resource: RoleAssignmentResource{
			Id:               "rsrc_123",
			ExternalId:       "ext-1",
			ResourceTypeSlug: "document",
		},
		CreatedAt: "2024-01-01T00:00:00.000Z",
		UpdatedAt: "2024-01-01T00:00:00.000Z",
	}

	data, err := json.Marshal(assignment)
	require.NoError(t, err)

	var decoded RoleAssignment
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, assignment, decoded)
}

func TestAuthorizationCheckResultJSON(t *testing.T) {
	result := AuthorizationCheckResult{Authorized: true}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded AuthorizationCheckResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.True(t, decoded.Authorized)

	result = AuthorizationCheckResult{Authorized: false}
	data, err = json.Marshal(result)
	require.NoError(t, err)
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.False(t, decoded.Authorized)
}

func TestAuthorizationOrganizationMembershipJSONRoundTrip(t *testing.T) {
	membership := AuthorizationOrganizationMembership{
		Object:         "organization_membership",
		Id:             "om_123",
		UserId:         "user_123",
		OrganizationId: "org_123",
		Status:         "active",
		CreatedAt:      "2024-01-01T00:00:00.000Z",
		UpdatedAt:      "2024-01-01T00:00:00.000Z",
		CustomAttributes: map[string]interface{}{
			"department": "engineering",
		},
	}

	data, err := json.Marshal(membership)
	require.NoError(t, err)

	var decoded AuthorizationOrganizationMembership
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, membership.Id, decoded.Id)
	require.Equal(t, membership.UserId, decoded.UserId)
	require.Equal(t, "engineering", decoded.CustomAttributes["department"])
}

// --- ResourceIdentifier interface tests ---

func TestResourceIdentifierByIdParams(t *testing.T) {
	id := ResourceIdentifierById{ResourceId: "rsrc_123"}
	params := id.resourceIdentifierParams()
	require.Equal(t, "rsrc_123", params["resource_id"])
	require.Len(t, params, 1)
}

func TestResourceIdentifierByExternalIdParams(t *testing.T) {
	id := ResourceIdentifierByExternalId{
		ResourceExternalId: "ext-1",
		ResourceTypeSlug:   "document",
	}
	params := id.resourceIdentifierParams()
	require.Equal(t, "ext-1", params["resource_external_id"])
	require.Equal(t, "document", params["resource_type_slug"])
	require.Len(t, params, 2)
}

func TestParentResourceIdentifierByIdParams(t *testing.T) {
	id := ParentResourceIdentifierById{ParentResourceId: "rsrc_parent"}
	params := id.parentResourceIdentifierParams()
	require.Equal(t, "rsrc_parent", params["parent_resource_id"])
	require.Len(t, params, 1)
}

func TestParentResourceIdentifierByExternalIdParams(t *testing.T) {
	id := ParentResourceIdentifierByExternalId{
		ParentResourceExternalId: "parent-ext-1",
		ParentResourceTypeSlug:   "folder",
	}
	params := id.parentResourceIdentifierParams()
	require.Equal(t, "parent-ext-1", params["parent_resource_external_id"])
	require.Equal(t, "folder", params["parent_resource_type_slug"])
	require.Len(t, params, 2)
}

// --- ResourceIdentifier satisfies interface ---

func TestResourceIdentifierByIdImplementsInterface(t *testing.T) {
	var _ ResourceIdentifier = ResourceIdentifierById{}
}

func TestResourceIdentifierByExternalIdImplementsInterface(t *testing.T) {
	var _ ResourceIdentifier = ResourceIdentifierByExternalId{}
}

func TestParentResourceIdentifierByIdImplementsInterface(t *testing.T) {
	var _ ParentResourceIdentifier = ParentResourceIdentifierById{}
}

func TestParentResourceIdentifierByExternalIdImplementsInterface(t *testing.T) {
	var _ ParentResourceIdentifier = ParentResourceIdentifierByExternalId{}
}

// --- Opts JSON serialization tests ---
// Verify that opts types marshal correctly with their json tags.

func TestCreateEnvironmentRoleOptsSerialization(t *testing.T) {
	opts := CreateEnvironmentRoleOpts{
		Slug:             "admin",
		Name:             "Admin",
		Description:      "Full access",
		ResourceTypeSlug: "document",
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, "admin", decoded["slug"])
	require.Equal(t, "Admin", decoded["name"])
	require.Equal(t, "Full access", decoded["description"])
	require.Equal(t, "document", decoded["resource_type_slug"])
}

func TestCreateEnvironmentRoleOptsOmitsEmptyOptionalFields(t *testing.T) {
	opts := CreateEnvironmentRoleOpts{
		Slug: "viewer",
		Name: "Viewer",
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	_, hasDescription := decoded["description"]
	require.False(t, hasDescription, "empty description should be omitted")
	_, hasResourceType := decoded["resource_type_slug"]
	require.False(t, hasResourceType, "empty resource_type_slug should be omitted")
}

func TestCreateOrganizationRoleOptsSerialization(t *testing.T) {
	opts := CreateOrganizationRoleOpts{
		OrganizationId: "org_123",
		Slug:           "editor",
		Name:           "Editor",
		Description:    "Can edit things",
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	// OrganizationId has json:"-" so should not appear in JSON body
	_, hasOrgId := decoded["organization_id"]
	require.False(t, hasOrgId, "OrganizationId should not be serialized in JSON body")
	require.Equal(t, "editor", decoded["slug"])
	require.Equal(t, "Editor", decoded["name"])
}

func TestCreatePermissionOptsSerialization(t *testing.T) {
	opts := CreatePermissionOpts{
		Slug:             "read",
		Name:             "Read",
		Description:      "Read access",
		ResourceTypeSlug: "document",
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, "read", decoded["slug"])
	require.Equal(t, "Read", decoded["name"])
	require.Equal(t, "Read access", decoded["description"])
	require.Equal(t, "document", decoded["resource_type_slug"])
}

func TestCreateAuthorizationResourceOptsSerialization(t *testing.T) {
	opts := CreateAuthorizationResourceOpts{
		ExternalId:       "ext-1",
		Name:             "My Doc",
		Description:      "A document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_123",
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, "ext-1", decoded["external_id"])
	require.Equal(t, "My Doc", decoded["name"])
	require.Equal(t, "document", decoded["resource_type_slug"])
	require.Equal(t, "org_123", decoded["organization_id"])
}

func TestUpdateResourceByExternalIdOptsSerialization(t *testing.T) {
	name := "Updated Name"
	desc := "Updated Desc"
	opts := UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		Name:             &name,
		Description:      &desc,
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	// Path params should not be in JSON body
	_, hasOrgId := decoded["organization_id"]
	require.False(t, hasOrgId)
	_, hasTypeSlug := decoded["resource_type_slug"]
	require.False(t, hasTypeSlug)
	_, hasExtId := decoded["external_id"]
	require.False(t, hasExtId)
	// Body fields should be present
	require.Equal(t, "Updated Name", decoded["name"])
	require.Equal(t, "Updated Desc", decoded["description"])
}

func TestUpdateResourceByExternalIdOptsNullDescription(t *testing.T) {
	// When Description is nil (null), it should still be present in JSON
	// because the tag is `json:"description"` (no omitempty)
	name := "Updated Name"
	opts := UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		Name:             &name,
		Description:      nil,
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	// Description should be present as null
	_, hasDesc := decoded["description"]
	require.True(t, hasDesc, "description field should be present even when nil")
	require.Nil(t, decoded["description"])
}

func TestSetEnvironmentRolePermissionsOptsSerialization(t *testing.T) {
	opts := SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read", "write", "delete"},
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	// Slug has json:"-"
	_, hasSlug := decoded["slug"]
	require.False(t, hasSlug)
	perms := decoded["permissions"].([]interface{})
	require.Len(t, perms, 3)
}

func TestAddEnvironmentRolePermissionOptsSerialization(t *testing.T) {
	opts := AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "delete",
	}
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	// Slug (role slug) has json:"-" so should be excluded
	// PermissionSlug uses json:"slug"
	require.Equal(t, "delete", decoded["slug"])
	require.Len(t, decoded, 1)
}

// --- List response deserialization tests ---

func TestListEnvironmentRolesResponseDeserialization(t *testing.T) {
	jsonStr := `{
		"data": [
			{
				"object": "authorization_role",
				"id": "role_123",
				"name": "Admin",
				"slug": "admin",
				"description": "Full access",
				"permissions": ["read", "write"],
				"resource_type_slug": "document",
				"type": "environment",
				"created_at": "2024-01-01T00:00:00.000Z",
				"updated_at": "2024-01-01T00:00:00.000Z"
			}
		]
	}`
	var resp ListEnvironmentRolesResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	require.Equal(t, "admin", resp.Data[0].Slug)
	require.Equal(t, []string{"read", "write"}, resp.Data[0].Permissions)
}

func TestListOrganizationRolesResponseDeserialization(t *testing.T) {
	jsonStr := `{
		"data": [
			{
				"object": "authorization_role",
				"id": "role_456",
				"name": "Editor",
				"slug": "editor",
				"description": "Can edit",
				"permissions": ["read", "write"],
				"resource_type_slug": "",
				"type": "organization",
				"created_at": "2024-01-01T00:00:00.000Z",
				"updated_at": "2024-01-01T00:00:00.000Z"
			}
		]
	}`
	var resp ListOrganizationRolesResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	require.Equal(t, "editor", resp.Data[0].Slug)
}

func TestListPermissionsResponseDeserialization(t *testing.T) {
	jsonStr := `{
		"data": [
			{
				"object": "authorization_permission",
				"id": "perm_123",
				"slug": "read",
				"name": "Read",
				"description": "Read access",
				"resource_type_slug": "document",
				"system": true,
				"created_at": "2024-01-01T00:00:00.000Z",
				"updated_at": "2024-01-01T00:00:00.000Z"
			}
		],
		"list_metadata": {
			"before": "before_cursor",
			"after": "after_cursor"
		}
	}`
	var resp ListPermissionsResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	require.True(t, resp.Data[0].System)
	require.Equal(t, "before_cursor", resp.ListMetadata.Before)
	require.Equal(t, "after_cursor", resp.ListMetadata.After)
}

func TestListAuthorizationResourcesResponseDeserialization(t *testing.T) {
	jsonStr := `{
		"data": [
			{
				"object": "authorization_resource",
				"id": "rsrc_123",
				"external_id": "ext-1",
				"name": "My Doc",
				"description": "A doc",
				"resource_type_slug": "document",
				"organization_id": "org_123",
				"parent_resource_id": "",
				"created_at": "2024-01-01T00:00:00.000Z",
				"updated_at": "2024-01-01T00:00:00.000Z"
			}
		],
		"list_metadata": {
			"before": "",
			"after": "cursor_abc"
		}
	}`
	var resp ListAuthorizationResourcesResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	require.Equal(t, "ext-1", resp.Data[0].ExternalId)
	require.Equal(t, "cursor_abc", resp.ListMetadata.After)
}

func TestListRoleAssignmentsResponseDeserialization(t *testing.T) {
	jsonStr := `{
		"data": [
			{
				"object": "role_assignment",
				"id": "ra_123",
				"role": {"slug": "admin"},
				"resource": {
					"id": "rsrc_123",
					"external_id": "ext-1",
					"resource_type_slug": "document"
				},
				"created_at": "2024-01-01T00:00:00.000Z",
				"updated_at": "2024-01-01T00:00:00.000Z"
			}
		],
		"list_metadata": {
			"before": "",
			"after": ""
		}
	}`
	var resp ListRoleAssignmentsResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	require.Equal(t, "admin", resp.Data[0].Role.Slug)
	require.Equal(t, "rsrc_123", resp.Data[0].Resource.Id)
}

func TestListAuthorizationOrganizationMembershipsResponseDeserialization(t *testing.T) {
	jsonStr := `{
		"data": [
			{
				"object": "organization_membership",
				"id": "om_123",
				"user_id": "user_123",
				"organization_id": "org_123",
				"status": "active",
				"created_at": "2024-01-01T00:00:00.000Z",
				"updated_at": "2024-01-01T00:00:00.000Z",
				"custom_attributes": {"level": "senior"}
			}
		],
		"list_metadata": {
			"before": "",
			"after": "cursor_123"
		}
	}`
	var resp ListAuthorizationOrganizationMembershipsResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	require.Equal(t, "om_123", resp.Data[0].Id)
	require.Equal(t, "senior", resp.Data[0].CustomAttributes["level"])
	require.Equal(t, "cursor_123", resp.ListMetadata.After)
}
