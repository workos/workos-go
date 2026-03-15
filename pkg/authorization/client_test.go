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
// ListResourcesForMembership
// ---------------------------------------------------------------------------

func TestListResourcesForMembership(t *testing.T) {
	listResourcesServer := func(capturedPath *string, capturedRawQuery *string, response ListAuthorizationResourcesResponse) *httptest.Server {
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

	singleItemResponse := ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{
			{
				Object:           "authorization_resource",
				Id:               "resource_01JF",
				ExternalId:       "my-doc-1",
				Name:             "My Document",
				Description:      "A test document",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_01JF",
				CreatedAt:        "2024-01-01T00:00:00.000Z",
				UpdatedAt:        "2024-01-01T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "resource_01JF"},
	}

	twoItemResponse := ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{
			{
				Object:           "authorization_resource",
				Id:               "resource_01JF",
				ResourceTypeSlug: "document",
				CreatedAt:        "2024-01-01T00:00:00.000Z",
				UpdatedAt:        "2024-01-01T00:00:00.000Z",
			},
			{
				Object:           "authorization_resource",
				Id:               "resource_02JF",
				ResourceTypeSlug: "document",
				CreatedAt:        "2024-01-02T00:00:00.000Z",
				UpdatedAt:        "2024-01-02T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "resource_02JF"},
	}

	emptyResponse := ListAuthorizationResourcesResponse{
		Data:         []AuthorizationResource{},
		ListMetadata: common.ListMetadata{},
	}

	expectedPath := "/authorization/organization_memberships/om_01JF/resources"

	t.Run("returns one resource", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("returns multiple resources and deserializes response", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, twoItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, "resource_01JF", result.Data[0].Id)
		require.Equal(t, "resource_02JF", result.Data[1].Id)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("returns zero resources", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, emptyResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes order desc", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Order:                    common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Order:                    common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=asc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Limit:                    25,
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=25")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Before:                   "cursor_before",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "before=cursor_before")
		require.NotContains(t, cQuery, "after=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			After:                    "cursor_after",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "after=cursor_after")
		require.NotContains(t, cQuery, "before=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes parent_resource_id in query", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			ParentResourceIdentifier: ParentResourceIdentifierById{
				ParentResourceId: "resource_parent_01",
			},
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "parent_resource_id=resource_parent_01")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes parent_resource_external_id and type_slug in query", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			ParentResourceIdentifier: ParentResourceIdentifierByExternalId{
				ParentResourceExternalId: "parent-ext-1",
				ParentResourceTypeSlug:   "folder",
			},
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "parent_resource_external_id=parent-ext-1")
		require.Contains(t, cQuery, "parent_resource_type_slug=folder")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var cPath, cQuery string
		server := listResourcesServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Limit:                    5,
			Before:                   "cursor_before",
			After:                    "cursor_after",
			Order:                    common.Asc,
		})

		require.NoError(t, err)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=5")
		require.Contains(t, cQuery, "before=cursor_before")
		require.Contains(t, cQuery, "after=cursor_after")
		require.Contains(t, cQuery, "order=asc")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}

		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "API key is required")
	})
}

// ---------------------------------------------------------------------------
// ListMembershipsForResource
// ---------------------------------------------------------------------------

func TestListMembershipsForResource(t *testing.T) {
	listMembershipsServer := func(capturedPath *string, capturedRawQuery *string, response ListAuthorizationOrganizationMembershipsResponse) *httptest.Server {
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

	singleItemResponse := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{
				Object:         "organization_membership",
				Id:             "om_01JF",
				UserId:         "user_01JF",
				OrganizationId: "org_01JF",
				Status:         MembershipStatusActive,
				CreatedAt:      "2024-01-01T00:00:00.000Z",
				UpdatedAt:      "2024-01-01T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "om_01JF"},
	}

	twoItemResponse := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{
				Object:         "organization_membership",
				Id:             "om_01JF",
				UserId:         "user_01JF",
				OrganizationId: "org_01JF",
				Status:         MembershipStatusActive,
				CreatedAt:      "2024-01-01T00:00:00.000Z",
				UpdatedAt:      "2024-01-01T00:00:00.000Z",
			},
			{
				Object:         "organization_membership",
				Id:             "om_02JF",
				UserId:         "user_02JF",
				OrganizationId: "org_01JF",
				Status:         MembershipStatusActive,
				CreatedAt:      "2024-01-02T00:00:00.000Z",
				UpdatedAt:      "2024-01-02T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "om_02JF"},
	}

	emptyResponse := ListAuthorizationOrganizationMembershipsResponse{
		Data:         []AuthorizationOrganizationMembership{},
		ListMetadata: common.ListMetadata{},
	}

	expectedPath := "/authorization/resources/resource_01JF/organization_memberships"

	t.Run("returns one membership", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("returns multiple memberships and deserializes response", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, twoItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, "om_01JF", result.Data[0].Id)
		require.Equal(t, "om_02JF", result.Data[1].Id)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("returns zero memberships", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, emptyResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes order desc", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Order:          common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Order:          common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=asc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Limit:          25,
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=25")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Before:         "cursor_before",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "before=cursor_before")
		require.NotContains(t, cQuery, "after=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			After:          "cursor_after",
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "after=cursor_after")
		require.NotContains(t, cQuery, "before=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes assignment filter", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Assignment:     AssignmentDirect,
		})

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "assignment=direct")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Assignment:     AssignmentDirect,
			Limit:          5,
			Before:         "cursor_before",
			After:          "cursor_after",
			Order:          common.Asc,
		})

		require.NoError(t, err)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=5")
		require.Contains(t, cQuery, "before=cursor_before")
		require.Contains(t, cQuery, "after=cursor_after")
		require.Contains(t, cQuery, "order=asc")
		require.Contains(t, cQuery, "assignment=direct")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}

		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "API key is required")
	})
}

// ---------------------------------------------------------------------------
// ListMembershipsForResourceByExternalId
// ---------------------------------------------------------------------------

func TestListMembershipsForResourceByExternalId(t *testing.T) {
	listMembershipsExtServer := func(capturedPath *string, capturedRawQuery *string, response ListAuthorizationOrganizationMembershipsResponse) *httptest.Server {
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

	singleItemResponse := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{
				Object:         "organization_membership",
				Id:             "om_01JF",
				UserId:         "user_01JF",
				OrganizationId: "org_01JF",
				Status:         MembershipStatusActive,
				CreatedAt:      "2024-01-01T00:00:00.000Z",
				UpdatedAt:      "2024-01-01T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "om_01JF"},
	}

	twoItemResponse := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{
				Object:         "organization_membership",
				Id:             "om_01JF",
				UserId:         "user_01JF",
				OrganizationId: "org_01JF",
				Status:         MembershipStatusActive,
				CreatedAt:      "2024-01-01T00:00:00.000Z",
				UpdatedAt:      "2024-01-01T00:00:00.000Z",
			},
			{
				Object:         "organization_membership",
				Id:             "om_02JF",
				UserId:         "user_02JF",
				OrganizationId: "org_01JF",
				Status:         MembershipStatusActive,
				CreatedAt:      "2024-01-02T00:00:00.000Z",
				UpdatedAt:      "2024-01-02T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "om_02JF"},
	}

	emptyResponse := ListAuthorizationOrganizationMembershipsResponse{
		Data:         []AuthorizationOrganizationMembership{},
		ListMetadata: common.ListMetadata{},
	}

	expectedPath := "/authorization/organizations/org_01JF/resources/document/my-doc-1/organization_memberships"

	baseOpts := func() ListMembershipsForResourceByExternalIdOpts {
		return ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		}
	}

	t.Run("returns one membership", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseOpts())

		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("returns multiple memberships and deserializes response", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, twoItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseOpts())

		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, "om_01JF", result.Data[0].Id)
		require.Equal(t, "om_02JF", result.Data[1].Id)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("returns zero memberships", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, emptyResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		result, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseOpts())

		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseOpts())

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes order desc", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		opts := baseOpts()
		opts.Order = common.Desc
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		opts := baseOpts()
		opts.Order = common.Asc
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=asc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseOpts())

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		opts := baseOpts()
		opts.Limit = 25
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=25")
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		opts := baseOpts()
		opts.Before = "cursor_before"
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "before=cursor_before")
		require.NotContains(t, cQuery, "after=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		opts := baseOpts()
		opts.After = "cursor_after"
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "after=cursor_after")
		require.NotContains(t, cQuery, "before=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes assignment filter", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		opts := baseOpts()
		opts.Assignment = AssignmentDirect
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)

		require.NoError(t, err)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=10")
		require.Contains(t, cQuery, "order=desc")
		require.Contains(t, cQuery, "assignment=direct")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var cPath, cQuery string
		server := listMembershipsExtServer(&cPath, &cQuery, singleItemResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)

		opts := baseOpts()
		opts.Assignment = AssignmentDirect
		opts.Limit = 5
		opts.Before = "cursor_before"
		opts.After = "cursor_after"
		opts.Order = common.Asc
		result, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)

		require.NoError(t, err)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, cPath)
		require.Contains(t, cQuery, "permission_slug=read%3Adocument")
		require.Contains(t, cQuery, "limit=5")
		require.Contains(t, cQuery, "before=cursor_before")
		require.Contains(t, cQuery, "after=cursor_after")
		require.Contains(t, cQuery, "order=asc")
		require.Contains(t, cQuery, "assignment=direct")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		client := newAuthorizationTestClient(server)

		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseOpts())
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}

		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseOpts())
		require.Error(t, err)
		require.Contains(t, err.Error(), "API key is required")
	})
}

func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}
