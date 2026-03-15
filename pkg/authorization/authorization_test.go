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

func TestListRoleAssignmentsWithDefaultClient(t *testing.T) {
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
		})
		require.Error(t, err)
	})
}

func TestAssignRoleWithDefaultClient(t *testing.T) {
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		result, err := AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01"},
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		result, err := AssignRole(context.Background(), AssignRoleOpts{
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01"},
		})
		require.Error(t, err)
	})
}

func TestRemoveRoleWithDefaultClient(t *testing.T) {
	t.Run("removes role with resource id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(noContentHandler(&capturedBody, &capturedPath)))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01"},
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := RemoveRole(context.Background(), RemoveRoleOpts{
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleSlug:                 "admin",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01"},
		})
		require.Error(t, err)
	})
}

func TestRemoveRoleAssignmentWithDefaultClient(t *testing.T) {
	t.Run("removes role assignment by id", func(t *testing.T) {
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, &capturedPath)))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
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

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			RoleAssignmentId:         "ra_01ABC",
		})
		require.Error(t, err)
	})
}
