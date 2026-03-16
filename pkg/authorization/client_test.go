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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool { return &b }

// newTestClient returns a Client wired to the given test server.
func newTestClient(server *httptest.Server, apiKey string) *Client {
	return &Client{
		APIKey:     apiKey,
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

// unauthorizedHandler rejects requests missing a valid Bearer token.
func unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
}

// ---------------------------------------------------------------------------
// PR #520-style Helpers
// ---------------------------------------------------------------------------

// jsonResponseHandler returns an http.HandlerFunc that checks auth, captures
// the request body and path, then responds with the given JSON payload.
func jsonResponseHandler(capturedBody *map[string]interface{}, capturedPath *string, response interface{}) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if capturedBody != nil {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				*capturedBody = body
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// noContentHandler returns an http.HandlerFunc that checks auth, captures
// the request body and path, then responds with 204 No Content.
func noContentHandler(capturedBody *map[string]interface{}, capturedPath *string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if capturedBody != nil {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				*capturedBody = body
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// Role Assignment Tests (PR #520 pattern)
// ---------------------------------------------------------------------------

func TestListRoleAssignments(t *testing.T) {
	singleItemResponse := ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object: "role_assignment",
				Id:     "ra_01ABC",
				Role:   RoleAssignmentRole{Slug: "admin"},
				Resource: RoleAssignmentResource{
					Id:               "resource_01ABC",
					ResourceTypeSlug: "document",
				},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}

	twoItemResponse := ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object: "role_assignment",
				Id:     "ra_01ABC",
				Role:   RoleAssignmentRole{Slug: "admin"},
				Resource: RoleAssignmentResource{
					Id:               "resource_01ABC",
					ResourceTypeSlug: "document",
				},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
			{
				Object: "role_assignment",
				Id:     "ra_02DEF",
				Role:   RoleAssignmentRole{Slug: "viewer"},
				Resource: RoleAssignmentResource{
					ExternalId:       "ext_456",
					ResourceTypeSlug: "folder",
				},
				CreatedAt: "2024-02-01T00:00:00Z",
				UpdatedAt: "2024-02-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "before_cursor",
			After:  "after_cursor",
		},
	}

	emptyResponse := ListRoleAssignmentsResponse{
		Data:         []RoleAssignment{},
		ListMetadata: common.ListMetadata{},
	}

	// listRoleAssignmentsServer creates a test server that captures path and
	// raw query, then returns the given response.
	listRoleAssignmentsServer := func(capturedPath *string, capturedRawQuery *string, response ListRoleAssignmentsResponse) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if capturedPath != nil {
				*capturedPath = r.URL.Path
			}
			if capturedRawQuery != nil {
				*capturedRawQuery = r.URL.RawQuery
			}
			if r.Header.Get("Authorization") != "Bearer test" {
				http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		}))
	}

	t.Run("returns one role assignment", func(t *testing.T) {
		var capturedPath string
		server := listRoleAssignmentsServer(&capturedPath, nil, singleItemResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		resp, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
		})
		require.NoError(t, err)
		require.Len(t, resp.Data, 1)
		require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", capturedPath)
	})

	t.Run("returns multiple role assignments and deserializes response", func(t *testing.T) {
		server := listRoleAssignmentsServer(nil, nil, twoItemResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		resp, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
		})
		require.NoError(t, err)
		require.Len(t, resp.Data, 2)
		require.Equal(t, "ra_01ABC", resp.Data[0].Id)
		require.Equal(t, "admin", resp.Data[0].Role.Slug)
		require.Equal(t, "resource_01ABC", resp.Data[0].Resource.Id)
		require.Equal(t, "ra_02DEF", resp.Data[1].Id)
		require.Equal(t, "viewer", resp.Data[1].Role.Slug)
		require.Equal(t, "ext_456", resp.Data[1].Resource.ExternalId)
		require.Equal(t, "before_cursor", resp.ListMetadata.Before)
		require.Equal(t, "after_cursor", resp.ListMetadata.After)
	})

	t.Run("returns zero role assignments", func(t *testing.T) {
		server := listRoleAssignmentsServer(nil, nil, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		resp, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
		})
		require.NoError(t, err)
		require.Empty(t, resp.Data)
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var capturedRawQuery string
		server := listRoleAssignmentsServer(nil, &capturedRawQuery, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("passes order desc", func(t *testing.T) {
		var capturedRawQuery string
		server := listRoleAssignmentsServer(nil, &capturedRawQuery, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
			Order:                    common.Desc,
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("passes order asc", func(t *testing.T) {
		var capturedRawQuery string
		server := listRoleAssignmentsServer(nil, &capturedRawQuery, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
			Order:                    common.Asc,
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=asc")
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var capturedRawQuery string
		server := listRoleAssignmentsServer(nil, &capturedRawQuery, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "limit=10")
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var capturedRawQuery string
		server := listRoleAssignmentsServer(nil, &capturedRawQuery, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
			Limit:                    25,
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "limit=25")
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var capturedRawQuery string
		server := listRoleAssignmentsServer(nil, &capturedRawQuery, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
			Before:                   "before_id",
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "before=before_id")
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var capturedRawQuery string
		server := listRoleAssignmentsServer(nil, &capturedRawQuery, emptyResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
			After:                    "after_id",
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "after=after_id")
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var capturedPath string
		var capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
			Limit:                    5,
			Before:                   "before_id",
			After:                    "after_id",
			Order:                    common.Asc,
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", capturedPath)
		require.Contains(t, capturedRawQuery, "limit=5")
		require.Contains(t, capturedRawQuery, "before=before_id")
		require.Contains(t, capturedRawQuery, "after=after_id")
		require.Contains(t, capturedRawQuery, "order=asc")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"server error"}`))
		}))
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01ABC",
		})
		require.Error(t, err)
	})
}

func TestAssignRole(t *testing.T) {
	assignRoleResponse := RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_01ABC",
		Role:   RoleAssignmentRole{Slug: "admin"},
		Resource: RoleAssignmentResource{
			Id:               "resource_01ABC",
			ResourceTypeSlug: "document",
		},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	}

	t.Run("assigns role with resource id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, assignRoleResponse),
		))
		defer server.Close()

		client := newTestClient(server, "test")
		resp, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
		})
		require.NoError(t, err)
		require.Equal(t, "ra_01ABC", resp.Id)
		require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", capturedPath)
		require.Equal(t, "admin", capturedBody["role_slug"])
		require.Equal(t, "resource_01ABC", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
	})

	t.Run("assigns role with resource external id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, assignRoleResponse),
		))
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleSlug:                 "admin",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext_123",
				ResourceTypeSlug:   "document",
			},
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", capturedPath)
		require.Equal(t, "admin", capturedBody["role_slug"])
		require.Equal(t, "ext_123", capturedBody["resource_external_id"])
		require.Equal(t, "document", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"server error"}`))
		}))
		defer server.Close()

		client := newTestClient(server, "test")
		_, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
		})
		require.Error(t, err)
	})
}

func TestRemoveRole(t *testing.T) {
	t.Run("removes role with resource id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			noContentHandler(&capturedBody, &capturedPath),
		))
		defer server.Close()

		client := newTestClient(server, "test")
		err := client.RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", capturedPath)
		require.Equal(t, "admin", capturedBody["role_slug"])
		require.Equal(t, "resource_01ABC", capturedBody["resource_id"])
	})

	t.Run("removes role with resource external id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			noContentHandler(&capturedBody, &capturedPath),
		))
		defer server.Close()

		client := newTestClient(server, "test")
		err := client.RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleSlug:                 "admin",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext_123",
				ResourceTypeSlug:   "document",
			},
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", capturedPath)
		require.Equal(t, "admin", capturedBody["role_slug"])
		require.Equal(t, "ext_123", capturedBody["resource_external_id"])
		require.Equal(t, "document", capturedBody["resource_type_slug"])
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"server error"}`))
		}))
		defer server.Close()

		client := newTestClient(server, "test")
		err := client.RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
		})
		require.Error(t, err)
	})
}

func TestRemoveRoleAssignment(t *testing.T) {
	t.Run("removes role assignment by id", func(t *testing.T) {
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			noContentHandler(nil, &capturedPath),
		))
		defer server.Close()

		client := newTestClient(server, "test")
		err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleAssignmentId:         "ra_01XYZ",
		})
		require.NoError(t, err)
		require.Contains(t, capturedPath, "ra_01XYZ")
		require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments/ra_01XYZ", capturedPath)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"server error"}`))
		}))
		defer server.Close()

		client := newTestClient(server, "test")
		err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
			OrganizationMembershipId: "om_01ABC",
			RoleAssignmentId:         "ra_01XYZ",
		})
		require.Error(t, err)
	})
}

func TestResourceIdentifierById_Params(t *testing.T) {
	r := ResourceIdentifierById{ResourceId: "resource_01ABC"}
	params := r.resourceIdentifierParams()
	require.Equal(t, "resource_01ABC", params["resource_id"])
	require.Len(t, params, 1)
}

func TestResourceIdentifierByExternalId_Params(t *testing.T) {
	r := ResourceIdentifierByExternalId{
		ResourceExternalId: "ext_123",
		ResourceTypeSlug:   "document",
	}
	params := r.resourceIdentifierParams()
	require.Equal(t, "ext_123", params["resource_external_id"])
	require.Equal(t, "document", params["resource_type_slug"])
	require.Len(t, params, 2)
}

func TestParentResourceIdentifierById_Params(t *testing.T) {
	r := ParentResourceIdentifierById{ParentResourceId: "parent_01ABC"}
	params := r.parentResourceIdentifierParams()
	require.Equal(t, "parent_01ABC", params["parent_resource_id"])
	require.Len(t, params, 1)
}

func TestParentResourceIdentifierByExternalId_Params(t *testing.T) {
	r := ParentResourceIdentifierByExternalId{
		ParentResourceExternalId: "ext_parent",
		ParentResourceTypeSlug:   "folder",
	}
	params := r.parentResourceIdentifierParams()
	require.Equal(t, "ext_parent", params["parent_resource_external_id"])
	require.Equal(t, "folder", params["parent_resource_type_slug"])
	require.Len(t, params, 2)
}

// ---------------------------------------------------------------------------
// Client Init Tests
// ---------------------------------------------------------------------------
