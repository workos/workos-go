package authorization

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

// resetDefaultClient wires DefaultClient to a test server and returns the server for cleanup.
func resetDefaultClient(handler http.Handler) *httptest.Server {
	server := httptest.NewServer(handler)
	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")
	return server
}

// ---------------------------------------------------------------------------
// Environment Roles (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationCreateEnvironmentRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(createEnvironmentRoleTestHandler))
	defer server.Close()

	role, err := CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "admin",
		Name: "Admin",
	})
	require.NoError(t, err)
	require.Equal(t, "role_01ABC", role.Id)
	require.Equal(t, "admin", role.Slug)
}

func TestAuthorizationListEnvironmentRoles(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(listEnvironmentRolesTestHandler))
	defer server.Close()

	roles, err := ListEnvironmentRoles(context.Background())
	require.NoError(t, err)
	require.Len(t, roles.Data, 2)
}

func TestAuthorizationGetEnvironmentRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(getEnvironmentRoleTestHandler))
	defer server.Close()

	role, err := GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.NoError(t, err)
	require.Equal(t, "admin", role.Slug)
}

func TestAuthorizationUpdateEnvironmentRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(updateEnvironmentRoleTestHandler))
	defer server.Close()

	name := "Super Admin"
	role, err := UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug: "admin",
		Name: &name,
	})
	require.NoError(t, err)
	require.Equal(t, "Super Admin", role.Name)
}

// ---------------------------------------------------------------------------
// Environment Role Permissions (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationSetEnvironmentRolePermissions(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		var opts SetEnvironmentRolePermissionsOpts
		json.NewDecoder(r.Body).Decode(&opts)
		writeJSON(w, http.StatusOK, EnvironmentRole{
			Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
			Permissions: opts.Permissions, Type: "environment",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	role, err := SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read", "write"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"read", "write"}, role.Permissions)
}

func TestAuthorizationAddEnvironmentRolePermission(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, EnvironmentRole{
			Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
			Permissions: []string{"read", "write", "delete"}, Type: "environment",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	role, err := AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "delete",
	})
	require.NoError(t, err)
	require.Contains(t, role.Permissions, "delete")
}

// ---------------------------------------------------------------------------
// Organization Roles (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationCreateOrganizationRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		var opts CreateOrganizationRoleOpts
		json.NewDecoder(r.Body).Decode(&opts)
		writeJSON(w, http.StatusOK, OrganizationRole{
			Object: "role", Id: "role_01ABC", Name: opts.Name, Slug: opts.Slug,
			Permissions: []string{}, Type: "organization",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	role, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Name:           "Editor",
	})
	require.NoError(t, err)
	require.Equal(t, "editor", role.Slug)
}

func TestAuthorizationListOrganizationRoles(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, ListOrganizationRolesResponse{
			Data: []OrganizationRole{{Object: "role", Id: "role_01ABC", Slug: "editor"}},
		})
	}))
	defer server.Close()

	roles, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})
	require.NoError(t, err)
	require.Len(t, roles.Data, 1)
}

func TestAuthorizationGetOrganizationRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, OrganizationRole{
			Object: "role", Id: "role_01ABC", Slug: "editor", Name: "Editor",
			Permissions: []string{}, Type: "organization",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	role, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
	})
	require.NoError(t, err)
	require.Equal(t, "editor", role.Slug)
}

func TestAuthorizationUpdateOrganizationRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, OrganizationRole{
			Object: "role", Id: "role_01ABC", Slug: "editor", Name: "Senior Editor",
			Permissions: []string{}, Type: "organization",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
		})
	}))
	defer server.Close()

	role, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Name:           stringPtr("Senior Editor"),
	})
	require.NoError(t, err)
	require.Equal(t, "Senior Editor", role.Name)
}

func TestAuthorizationDeleteOrganizationRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Organization Role Permissions (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationSetOrganizationRolePermissions(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		var opts SetOrganizationRolePermissionsOpts
		json.NewDecoder(r.Body).Decode(&opts)
		writeJSON(w, http.StatusOK, OrganizationRole{
			Object: "role", Id: "role_01ABC", Slug: "editor",
			Permissions: opts.Permissions, Type: "organization",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	role, err := SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_01ABC", Slug: "editor",
		Permissions: []string{"read", "write"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"read", "write"}, role.Permissions)
}

func TestAuthorizationAddOrganizationRolePermission(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, OrganizationRole{
			Object: "role", Id: "role_01ABC", Slug: "editor",
			Permissions: []string{"read", "write", "delete"}, Type: "organization",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	role, err := AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC", Slug: "editor", PermissionSlug: "delete",
	})
	require.NoError(t, err)
	require.Contains(t, role.Permissions, "delete")
}

func TestAuthorizationRemoveOrganizationRolePermission(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC", Slug: "editor", PermissionSlug: "delete",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Permissions (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationCreatePermission(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		var opts CreatePermissionOpts
		json.NewDecoder(r.Body).Decode(&opts)
		writeJSON(w, http.StatusOK, Permission{
			Object: "permission", Id: "perm_01ABC", Slug: opts.Slug, Name: opts.Name,
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	perm, err := CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "read", Name: "Read",
	})
	require.NoError(t, err)
	require.Equal(t, "read", perm.Slug)
}

func TestAuthorizationListPermissions(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, ListPermissionsResponse{
			Data: []Permission{{Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read"}},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
	}))
	defer server.Close()

	perms, err := ListPermissions(context.Background(), ListPermissionsOpts{})
	require.NoError(t, err)
	require.Len(t, perms.Data, 1)
}

func TestAuthorizationGetPermission(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, Permission{
			Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	perm, err := GetPermission(context.Background(), GetPermissionOpts{Slug: "read"})
	require.NoError(t, err)
	require.Equal(t, "read", perm.Slug)
}

func TestAuthorizationUpdatePermission(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, Permission{
			Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read Access",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
		})
	}))
	defer server.Close()

	perm, err := UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "read", Name: stringPtr("Read Access"),
	})
	require.NoError(t, err)
	require.Equal(t, "Read Access", perm.Name)
}

func TestAuthorizationDeletePermission(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := DeletePermission(context.Background(), DeletePermissionOpts{Slug: "read"})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Resources (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationGetResource(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, AuthorizationResource{
			Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
			Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	res, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.NoError(t, err)
	require.Equal(t, "res_01ABC", res.Id)
}

func TestAuthorizationCreateResource(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		var bodyMap map[string]interface{}
		json.Unmarshal(bodyBytes, &bodyMap)

		writeJSON(w, http.StatusOK, AuthorizationResource{
			Object: "authorization_resource", Id: "res_01ABC",
			ExternalId: bodyMap["external_id"].(string), Name: bodyMap["name"].(string),
			ResourceTypeSlug: bodyMap["resource_type_slug"].(string),
			OrganizationId:   bodyMap["organization_id"].(string),
			CreatedAt:        "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	res, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId: "doc-1", Name: "Document 1",
		ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
	})
	require.NoError(t, err)
	require.Equal(t, "doc-1", res.ExternalId)
}

func TestAuthorizationUpdateResource(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, AuthorizationResource{
			Object: "authorization_resource", Id: "res_01ABC",
			Name: "Updated Doc", ResourceTypeSlug: "document",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
		})
	}))
	defer server.Close()

	res, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId: "res_01ABC", Name: stringPtr("Updated Doc"),
	})
	require.NoError(t, err)
	require.Equal(t, "Updated Doc", res.Name)
}

func TestAuthorizationDeleteResource(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.NoError(t, err)
}

func TestAuthorizationListResources(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, ListAuthorizationResourcesResponse{
			Data: []AuthorizationResource{
				{Object: "authorization_resource", Id: "res_01ABC", Name: "Document 1"},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
	}))
	defer server.Close()

	res, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{})
	require.NoError(t, err)
	require.Len(t, res.Data, 1)
}

// ---------------------------------------------------------------------------
// Resources by External Id (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationGetResourceByExternalId(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, AuthorizationResource{
			Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
			Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	res, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
	})
	require.NoError(t, err)
	require.Equal(t, "doc-1", res.ExternalId)
}

func TestAuthorizationUpdateResourceByExternalId(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, AuthorizationResource{
			Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
			Name: "Updated", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
		})
	}))
	defer server.Close()

	res, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
		Name: stringPtr("Updated"),
	})
	require.NoError(t, err)
	require.Equal(t, "Updated", res.Name)
}

func TestAuthorizationDeleteResourceByExternalId(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Check (package-level wrapper)
// ---------------------------------------------------------------------------

func TestAuthorizationCheck(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, AuthorizationCheckResult{Authorized: true})
	}))
	defer server.Close()

	result, err := Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "read",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.NoError(t, err)
	require.True(t, result.Authorized)
}

// ---------------------------------------------------------------------------
// Role Assignments (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationListRoleAssignments(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, ListRoleAssignmentsResponse{
			Data: []RoleAssignment{
				{Object: "role_assignment", Id: "ra_01ABC", Role: RoleAssignmentRole{Slug: "admin"}},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
	}))
	defer server.Close()

	result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01ABC",
	})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
}

func TestAuthorizationAssignRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, RoleAssignment{
			Object: "role_assignment", Id: "ra_01ABC",
			Role:     RoleAssignmentRole{Slug: "admin"},
			Resource: RoleAssignmentResource{Id: "res_01ABC"},
		})
	}))
	defer server.Close()

	result, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.NoError(t, err)
	require.Equal(t, "admin", result.Role.Slug)
}

func TestAuthorizationRemoveRole(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.NoError(t, err)
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleAssignmentId:         "ra_01ABC",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Membership / Resource queries (package-level wrappers)
// ---------------------------------------------------------------------------

func TestAuthorizationListResourcesForMembership(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, ListAuthorizationResourcesResponse{
			Data: []AuthorizationResource{
				{Object: "authorization_resource", Id: "res_01ABC", Name: "Document 1"},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
	}))
	defer server.Close()

	result, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "read",
	})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
}

func TestAuthorizationListMembershipsForResource(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, ListAuthorizationOrganizationMembershipsResponse{
			Data: []AuthorizationOrganizationMembership{
				{Object: "organization_membership", Id: "om_01ABC", Status: "active"},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
	}))
	defer server.Close()

	result, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "res_01ABC",
		PermissionSlug: "read",
	})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
}

func TestAuthorizationListMembershipsForResourceByExternalId(t *testing.T) {
	server := resetDefaultClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authGuard(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, ListAuthorizationOrganizationMembershipsResponse{
			Data: []AuthorizationOrganizationMembership{
				{Object: "organization_membership", Id: "om_01ABC", Status: "active"},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
	}))
	defer server.Close()

	result, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
		PermissionSlug: "read",
	})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
}
