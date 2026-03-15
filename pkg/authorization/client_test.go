package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// ---- Environment Role fixtures ----

var environmentRoleFixture = EnvironmentRole{
	Object:           "role",
	Id:               "role_env_001",
	Name:             "Admin",
	Slug:             "admin",
	Description:      "Full administrative access",
	Permissions:      []string{"users:read", "users:write", "settings:manage"},
	ResourceTypeSlug: "organization",
	Type:             "EnvironmentRole",
	CreatedAt:        "2024-01-01T00:00:00Z",
	UpdatedAt:        "2024-01-01T00:00:00Z",
}

var listEnvironmentRolesFixture = ListEnvironmentRolesResponse{
	Data: []EnvironmentRole{
		{
			Object:           "role",
			Id:               "role_env_001",
			Name:             "Admin",
			Slug:             "admin",
			Description:      "Full administrative access",
			Permissions:      []string{"users:read", "users:write", "settings:manage"},
			ResourceTypeSlug: "organization",
			Type:             "EnvironmentRole",
			CreatedAt:        "2024-01-01T00:00:00Z",
			UpdatedAt:        "2024-01-01T00:00:00Z",
		},
		{
			Object:           "role",
			Id:               "role_env_002",
			Name:             "Member",
			Slug:             "member",
			Description:      "Basic member access",
			Permissions:      []string{"users:read"},
			ResourceTypeSlug: "organization",
			Type:             "EnvironmentRole",
			CreatedAt:        "2024-01-02T00:00:00Z",
			UpdatedAt:        "2024-01-02T00:00:00Z",
		},
	},
}

// ---- Organization Role fixtures ----

var organizationRoleFixture = OrganizationRole{
	Object:           "role",
	Id:               "role_org_001",
	Name:             "Org Admin",
	Slug:             "org-admin",
	Description:      "Organization administrator",
	Permissions:      []string{"org:manage", "members:invite"},
	ResourceTypeSlug: "organization",
	Type:             "OrganizationRole",
	CreatedAt:        "2024-01-01T00:00:00Z",
	UpdatedAt:        "2024-01-01T00:00:00Z",
}

var listOrganizationRolesFixture = ListOrganizationRolesResponse{
	Data: []OrganizationRole{
		organizationRoleFixture,
		{
			Object:           "role",
			Id:               "role_org_002",
			Name:             "Org Member",
			Slug:             "org-member",
			Description:      "Basic org member",
			Permissions:      []string{"org:read"},
			ResourceTypeSlug: "organization",
			Type:             "OrganizationRole",
			CreatedAt:        "2024-01-02T00:00:00Z",
			UpdatedAt:        "2024-01-02T00:00:00Z",
		},
	},
}

// ---- Permission fixtures ----

var permissionFixture = Permission{
	Object:           "permission",
	Id:               "perm_001",
	Slug:             "users:read",
	Name:             "Read Users",
	Description:      "Allows reading user data",
	ResourceTypeSlug: "organization",
	System:           false,
	CreatedAt:        "2024-01-01T00:00:00Z",
	UpdatedAt:        "2024-01-01T00:00:00Z",
}

var listPermissionsFixture = ListPermissionsResponse{
	Data: []Permission{
		permissionFixture,
		{
			Object:           "permission",
			Id:               "perm_002",
			Slug:             "users:write",
			Name:             "Write Users",
			Description:      "Allows modifying user data",
			ResourceTypeSlug: "organization",
			System:           false,
			CreatedAt:        "2024-01-02T00:00:00Z",
			UpdatedAt:        "2024-01-02T00:00:00Z",
		},
	},
	ListMetadata: common.ListMetadata{
		Before: "",
		After:  "perm_002",
	},
}

// ---- Role Assignment fixtures ----

var roleAssignmentFixture = RoleAssignment{
	Object: "role_assignment",
	Id:     "ra_001",
	Role:   RoleAssignmentRole{Slug: "admin"},
	Resource: RoleAssignmentResource{
		Id:               "resource_123",
		ExternalId:       "ext_123",
		ResourceTypeSlug: "document",
	},
	CreatedAt: "2024-01-01T00:00:00Z",
	UpdatedAt: "2024-01-01T00:00:00Z",
}

var listRoleAssignmentsFixture = ListRoleAssignmentsResponse{
	Data: []RoleAssignment{roleAssignmentFixture},
	ListMetadata: common.ListMetadata{
		Before: "",
		After:  "ra_001",
	},
}

// ---- Membership fixtures ----

var membershipFixture = AuthorizationOrganizationMembership{
	Object:         "organization_membership",
	Id:             "om_001",
	UserId:         "user_123",
	OrganizationId: "org_123",
	Status:         "active",
	CreatedAt:      "2024-01-01T00:00:00Z",
	UpdatedAt:      "2024-01-01T00:00:00Z",
}

var listMembershipsFixture = ListAuthorizationOrganizationMembershipsResponse{
	Data: []AuthorizationOrganizationMembership{membershipFixture},
	ListMetadata: common.ListMetadata{
		Before: "",
		After:  "om_001",
	},
}

// ===========================================================================
// Environment Roles
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
// Organization Roles
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
// Permissions
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

	tests := []struct {
		scenario string
		client   *Client
		options  CreateAuthorizationResourceOpts
		handler  http.HandlerFunc
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			err: true,
		},
		{
			scenario: "Request creates resource with parent by ID",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:               "ext_123",
				Name:                     "Test Resource",
				ResourceTypeSlug:         "document",
				OrganizationId:           "org_123",
				ParentResourceIdentifier: ParentResourceIdentifierById{ParentResourceId: "parent_123"},
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: &parentId,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource with parent by external ID",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceIdentifier: ParentResourceIdentifierByExternalId{
					ParentResourceExternalId: "parent_ext_123",
					ParentResourceTypeSlug:   "folder",
				},
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: &parentId,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource without parent",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithoutParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource without description",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithoutDescriptionTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource with description",
			client:   &Client{APIKey: "test"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				if !authHandler(w, r) {
					return
				}
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if r.URL.Path != "/authorization/resources" {
					http.Error(w, "invalid path", http.StatusNotFound)
					return
				}
				var reqBody map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
					http.Error(w, "invalid request body", http.StatusBadRequest)
					return
				}
				if _, has := reqBody["description"]; !has {
					http.Error(w, "expected description in request body", http.StatusBadRequest)
					return
				}
				jsonResponse(w, http.StatusOK, resourceResponse("resource_new", "ext_123", "Test Resource", ptr("A resource"), nil, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"))
			},
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      ptr("A resource"),
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			expected: resourceResponse("resource_new", "ext_123", "Test Resource", ptr("A resource"), nil, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.CreateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func TestGetResource(t *testing.T) {
	testDesc := "A test resource"
	parentId := "parent_123"

	tests := []struct {
		scenario string
		client   *Client
		options  GetAuthorizationResourceOpts
		handler  http.HandlerFunc
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			handler:  getResourceAllFieldsHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			err:      true,
		},
		{
			scenario: "Request returns resource with all fields",
			client:   &Client{APIKey: "test"},
			handler:  getResourceAllFieldsHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
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
			},
		},
		{
			scenario: "Request returns resource without parent",
			client:   &Client{APIKey: "test"},
			handler:  getResourceWithoutParentHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      &testDesc,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: nil,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request returns resource without description",
			client:   &Client{APIKey: "test"},
			handler:  getResourceWithoutDescriptionHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: &parentId,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request returns resource without parent and description",
			client:   &Client{APIKey: "test"},
			handler:  getResourceWithoutParentAndDescriptionHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: nil,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.GetResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func TestUpdateResource(t *testing.T) {
	originalName := "Test Resource"
	newName := "Updated Resource"
	originalDesc := "A test resource"
	newDesc := "Updated description"

	tests := []struct {
		scenario string
		client   *Client
		options  UpdateAuthorizationResourceOpts
		handler  http.HandlerFunc
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			handler:  updateResourceTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId: "resource_123",
				Name:       &newName,
			},
			err: true,
		},
		{
			scenario: "Updates name and description",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId:  "resource_123",
				Name:        &newName,
				Description: &newDesc,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             newName,
				Description:      &newDesc,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Updates name only",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceNameOnlyTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId: "resource_123",
				Name:       &newName,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             newName,
				Description:      &originalDesc,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Updates description only",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceDescriptionOnlyTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId:  "resource_123",
				Description: &newDesc,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             originalName,
				Description:      &newDesc,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Sets description to null",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceNullDescriptionTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId: "resource_123",
				Name:       &newName,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             newName,
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.UpdateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func TestDeleteResource(t *testing.T) {
	tests := []struct {
		scenario              string
		client                *Client
		options               DeleteAuthorizationResourceOpts
		expectedCascadeDelete string
		err                   bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			options:  DeleteAuthorizationResourceOpts{ResourceId: "resource_123"},
			err:      true,
		},
		{
			scenario: "Delete without cascade succeeds",
			client:   &Client{APIKey: "test"},
			options: DeleteAuthorizationResourceOpts{
				ResourceId: "resource_123",
			},
			expectedCascadeDelete: "",
		},
		{
			scenario: "Delete with cascade true sets cascade_delete query param",
			client:   &Client{APIKey: "test"},
			options: DeleteAuthorizationResourceOpts{
				ResourceId:    "resource_123",
				CascadeDelete: true,
			},
			expectedCascadeDelete: "true",
		},
		{
			scenario: "Delete with cascade false omits cascade_delete query param",
			client:   &Client{APIKey: "test"},
			options: DeleteAuthorizationResourceOpts{
				ResourceId:    "resource_123",
				CascadeDelete: false,
			},
			expectedCascadeDelete: "",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

				if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
					http.Error(w, "invalid path", http.StatusNotFound)
					return
				}

				if r.Method != http.MethodDelete {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}

				require.Equal(t, test.expectedCascadeDelete, r.URL.Query().Get("cascade_delete"))

				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeleteResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestListResources(t *testing.T) {
	firstDesc := "First resource"
	parentId := "parent_001"

	tests := []struct {
		scenario       string
		client         *Client
		options        ListAuthorizationResourcesOpts
		handler        http.HandlerFunc
		expected       ListAuthorizationResourcesResponse
		expectedParams map[string]string
		err            bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			options:  ListAuthorizationResourcesOpts{},
			handler:  listResourcesTestHandler,
			err:      true,
		},
		{
			scenario: "Request returns paginated resources",
			client:   &Client{APIKey: "test"},
			options:  ListAuthorizationResourcesOpts{},
			handler:  listResourcesTestHandler,
			expected: ListAuthorizationResourcesResponse{
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
			},
		},
		{
			scenario: "Filters by organization and resource type",
			client:   &Client{APIKey: "test"},
			options: ListAuthorizationResourcesOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
			},
			expectedParams: map[string]string{
				"organization_id":    "org_123",
				"resource_type_slug": "document",
			},
		},
		{
			scenario: "Paginates forward with after cursor",
			client:   &Client{APIKey: "test"},
			options: ListAuthorizationResourcesOpts{
				Limit: 5,
				After: "resource_001",
				Order: common.Desc,
			},
			expectedParams: map[string]string{
				"limit": "5",
				"after": "resource_001",
				"order": "desc",
			},
		},
		{
			scenario: "Paginates backward with before cursor",
			client:   &Client{APIKey: "test"},
			options: ListAuthorizationResourcesOpts{
				Limit:  5,
				Before: "resource_002",
				Order:  common.Asc,
			},
			expectedParams: map[string]string{
				"limit":  "5",
				"before": "resource_002",
				"order":  "asc",
			},
		},
		{
			scenario: "Filters by parent resource id",
			client:   &Client{APIKey: "test"},
			options: ListAuthorizationResourcesOpts{
				ParentResourceId: "parent_001",
			},
			expectedParams: map[string]string{
				"parent_resource_id": "parent_001",
			},
		},
		{
			scenario: "Filters by parent external id and type slug",
			client:   &Client{APIKey: "test"},
			options: ListAuthorizationResourcesOpts{
				ParentResourceTypeSlug: "folder",
				ParentExternalId:       "folder-123",
			},
			expectedParams: map[string]string{
				"parent_resource_type_slug": "folder",
				"parent_external_id":        "folder-123",
			},
		},
		{
			scenario: "Filters by search term",
			client:   &Client{APIKey: "test"},
			options: ListAuthorizationResourcesOpts{
				Search: "Budget",
			},
			expectedParams: map[string]string{
				"search": "Budget",
			},
		},
		{
			scenario: "Applies default limit of 10",
			client:   &Client{APIKey: "test"},
			options:  ListAuthorizationResourcesOpts{},
			expectedParams: map[string]string{
				"limit": "10",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			handler := test.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, r *http.Request) {
					auth := r.Header.Get("Authorization")
					if auth != "Bearer test" {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}

					for key, val := range test.expectedParams {
						require.Equal(t, val, r.URL.Query().Get(key))
					}

					body, _ := json.Marshal(ListAuthorizationResourcesResponse{
						Data:         []AuthorizationResource{},
						ListMetadata: common.ListMetadata{},
					})
					w.WriteHeader(http.StatusOK)
					w.Write(body)
				}
			}

			server := httptest.NewServer(http.HandlerFunc(handler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resources, err := client.ListResources(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if test.expected.Data != nil {
				require.Equal(t, test.expected, resources)
			}
		})
	}
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

// ===========================================================================
// Test Handlers (shared by resource tests)
// ===========================================================================

func createResourceWithParentTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_, hasParentId := reqBody["parent_resource_id"]
	_, hasParentExtId := reqBody["parent_resource_external_id"]
	if !hasParentId && !hasParentExtId {
		http.Error(w, "expected parent fields in request body", http.StatusBadRequest)
		return
	}
	jsonResponse(w, http.StatusOK, createdResourceWithParent)
}

func createResourceWithoutParentTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if _, has := reqBody["parent_resource_id"]; has {
		http.Error(w, "unexpected parent_resource_id", http.StatusBadRequest)
		return
	}
	if _, has := reqBody["parent_resource_external_id"]; has {
		http.Error(w, "unexpected parent_resource_external_id", http.StatusBadRequest)
		return
	}
	jsonResponse(w, http.StatusOK, createdResourceWithoutParent)
}

func createResourceWithoutDescriptionTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if _, has := reqBody["description"]; has {
		http.Error(w, "unexpected description", http.StatusBadRequest)
		return
	}
	jsonResponse(w, http.StatusOK, createdResourceWithoutParent)
}

func getResourceAllFieldsHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, existingResourceAllFields)
}

func getResourceWithoutParentHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, existingResourceNoParent)
}

func getResourceWithoutDescriptionHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, existingResourceNoDesc)
}

func getResourceWithoutParentAndDescriptionHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, existingResourceMinimal)
}

func updateResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, updatedResourceFull)
}

func updateResourceNameOnlyTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, updatedResourceNameOnly)
}

func updateResourceDescriptionOnlyTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, updatedResourceDescOnly)
}

func updateResourceNullDescriptionTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, updatedResourceNullDesc)
}

func deleteResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func listResourcesTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authHandler(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{
			resourceResponse("resource_001", "ext_001", "Resource One", ptr("First resource"), ptr("parent_001"), "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
			resourceResponse("resource_002", "ext_002", "Resource Two", nil, nil, "2024-01-02T00:00:00Z", "2024-01-02T00:00:00Z"),
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "resource_002",
		},
	})
}
