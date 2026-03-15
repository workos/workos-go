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

func TestListRoleAssignments(t *testing.T) {
	t.Run("returns role assignments", func(t *testing.T) {
		var capturedPath string

		response := ListRoleAssignmentsResponse{
			Data: []RoleAssignment{
				{
					Object: "role_assignment",
					Id:     "ra_01ABC",
					Role:   RoleAssignmentRole{Slug: "admin"},
					Resource: RoleAssignmentResource{
						Id:               "resource_01",
						ExternalId:       "ext-1",
						ResourceTypeSlug: "project",
					},
					CreatedAt: "2024-01-01T00:00:00Z",
					UpdatedAt: "2024-01-01T00:00:00Z",
				},
				{
					Object: "role_assignment",
					Id:     "ra_02DEF",
					Role:   RoleAssignmentRole{Slug: "viewer"},
					Resource: RoleAssignmentResource{
						Id:               "resource_02",
						ExternalId:       "ext-2",
						ResourceTypeSlug: "document",
					},
					CreatedAt: "2024-01-02T00:00:00Z",
					UpdatedAt: "2024-01-02T00:00:00Z",
				},
			},
			ListMetadata: common.ListMetadata{
				Before: "",
				After:  "ra_02DEF",
			},
		}

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, &capturedPath, response)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			Limit:                    10,
		})

		require.NoError(t, err)
		require.Equal(t, response, result)
		require.Equal(t, "/authorization/organization_memberships/om_01JKR3PB/role_assignments", capturedPath)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
		})
		require.Error(t, err)
	})
}

func TestAssignRole(t *testing.T) {
	t.Run("assigns role with resource id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		response := RoleAssignment{
			Object: "role_assignment",
			Id:     "ra_01ABC",
			Role:   RoleAssignmentRole{Slug: "admin"},
			Resource: RoleAssignmentResource{
				Id:               "resource_01",
				ResourceTypeSlug: "project",
			},
			CreatedAt: "2024-01-01T00:00:00Z",
			UpdatedAt: "2024-01-01T00:00:00Z",
		}

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(&capturedBody, &capturedPath, response)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:      ResourceIdentifierById{ResourceId: "resource_01"},
		})

		require.NoError(t, err)
		require.Equal(t, response, result)
		require.Equal(t, "/authorization/organization_memberships/om_01JKR3PB/role_assignments", capturedPath)
		require.Equal(t, "admin", capturedBody["role_slug"])
		require.Equal(t, "resource_01", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("assigns role with resource external id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		response := RoleAssignment{
			Object: "role_assignment",
			Id:     "ra_03GHI",
			Role:   RoleAssignmentRole{Slug: "editor"},
			Resource: RoleAssignmentResource{
				ExternalId:       "ext-resource-42",
				ResourceTypeSlug: "document",
			},
			CreatedAt: "2024-01-03T00:00:00Z",
			UpdatedAt: "2024-01-03T00:00:00Z",
		}

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(&capturedBody, &capturedPath, response)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "editor",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext-resource-42",
				ResourceTypeSlug:   "document",
			},
		})

		require.NoError(t, err)
		require.Equal(t, response, result)
		require.Equal(t, "/authorization/organization_memberships/om_01JKR3PB/role_assignments", capturedPath)
		require.Equal(t, "editor", capturedBody["role_slug"])
		require.Equal(t, "ext-resource-42", capturedBody["resource_external_id"])
		require.Equal(t, "document", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		_, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:      ResourceIdentifierById{ResourceId: "resource_01"},
		})
		require.Error(t, err)
	})
}

func TestRemoveRole(t *testing.T) {
	t.Run("removes role with resource id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(noContentHandler(&capturedBody, &capturedPath)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:      ResourceIdentifierById{ResourceId: "resource_01"},
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/om_01JKR3PB/role_assignments", capturedPath)
		require.Equal(t, "admin", capturedBody["role_slug"])
		require.Equal(t, "resource_01", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("removes role with resource external id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(noContentHandler(&capturedBody, &capturedPath)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "editor",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext-resource-42",
				ResourceTypeSlug:   "document",
			},
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/om_01JKR3PB/role_assignments", capturedPath)
		require.Equal(t, "editor", capturedBody["role_slug"])
		require.Equal(t, "ext-resource-42", capturedBody["resource_external_id"])
		require.Equal(t, "document", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:      ResourceIdentifierById{ResourceId: "resource_01"},
		})
		require.Error(t, err)
	})
}

func TestRemoveRoleAssignment(t *testing.T) {
	t.Run("removes role assignment by id", func(t *testing.T) {
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, &capturedPath)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleAssignmentId:         "ra_01ABC",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/om_01JKR3PB/role_assignments/ra_01ABC", capturedPath)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleAssignmentId:         "ra_01ABC",
		})
		require.Error(t, err)
	})
}

// Test helpers

func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

// jsonResponseHandler creates a handler that captures request body and path,
// then returns the given response as JSON with 200 OK.
func jsonResponseHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
	response interface{},
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		if capturedBody != nil {
			if err := json.NewDecoder(r.Body).Decode(capturedBody); err != nil {
				http.Error(w, "failed to decode body", http.StatusBadRequest)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}
}

// noContentHandler creates a handler that captures request body and path,
// then returns 204 No Content.
func noContentHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		if capturedBody != nil {
			if err := json.NewDecoder(r.Body).Decode(capturedBody); err != nil {
				http.Error(w, "failed to decode body", http.StatusBadRequest)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
