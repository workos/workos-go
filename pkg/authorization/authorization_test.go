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

func TestListRoleAssignmentsWithDefaultClient(t *testing.T) {
	listRoleAssignmentsServer := func(capturedPath *string, capturedRawQuery *string, response ListRoleAssignmentsResponse) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedRawQuery = r.URL.RawQuery

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
		}))
	}

	singleItemResponse := ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object:    "role_assignment",
				Id:        "ra_01ABC",
				Role:      RoleAssignmentRole{Slug: "admin"},
				Resource:  RoleAssignmentResource{Id: "resource_01", ResourceTypeSlug: "project"},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "ra_01ABC"},
	}

	emptyResponse := ListRoleAssignmentsResponse{
		Data:         []RoleAssignment{},
		ListMetadata: common.ListMetadata{},
	}

	twoItemResponse := ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object:    "role_assignment",
				Id:        "ra_01ABC",
				Role:      RoleAssignmentRole{Slug: "admin"},
				Resource:  RoleAssignmentResource{Id: "resource_01", ResourceTypeSlug: "project"},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
			{
				Object:    "role_assignment",
				Id:        "ra_02DEF",
				Role:      RoleAssignmentRole{Slug: "member"},
				Resource:  RoleAssignmentResource{Id: "resource_02", ResourceTypeSlug: "project"},
				CreatedAt: "2024-01-02T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "ra_02DEF"},
	}

	expectedPath := "/authorization/organization_memberships/om_01JKR3PB/role_assignments"

	t.Run("returns one role assignment", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("returns multiple role assignments and deserializes response", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, twoItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, twoItemResponse, result)
		require.Equal(t, "ra_01ABC", result.Data[0].Id)
		require.Equal(t, "admin", result.Data[0].Role.Slug)
		require.Equal(t, "ra_02DEF", result.Data[1].Id)
		require.Equal(t, "member", result.Data[1].Role.Slug)
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("returns zero role assignments", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, emptyResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
		})

		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order desc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			Order:                    common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			Order:                    common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=asc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			Limit:                    25,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "limit=25")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			Before:                   "ra_cursor_before",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "before=ra_cursor_before")
		require.NotContains(t, capturedRawQuery, "after=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			After:                    "ra_cursor_after",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "after=ra_cursor_after")
		require.NotContains(t, capturedRawQuery, "before=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listRoleAssignmentsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
			OrganizationMembershipId: "om_01JKR3PB",
			Limit:                    5,
			Before:                   "ra_before",
			After:                    "ra_after",
			Order:                    common.Asc,
		})

		require.NoError(t, err)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "limit=5")
		require.Contains(t, capturedRawQuery, "before=ra_before")
		require.Contains(t, capturedRawQuery, "after=ra_after")
		require.Contains(t, capturedRawQuery, "order=asc")
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
