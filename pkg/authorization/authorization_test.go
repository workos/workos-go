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

// setupDefaultClient replaces the global DefaultClient with one pointing at
// the given test server. It returns a cleanup function that restores the
// original DefaultClient.
func setupDefaultClient(server *httptest.Server) func() {
	original := DefaultClient
	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")
	return func() {
		DefaultClient = original
	}
}

func TestAuthorizationListResourcesForMembershipWithDefaultClient(t *testing.T) {
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
				ExternalId:       "my-doc-1",
				Name:             "My Document",
				Description:      "A test document",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_01JF",
				CreatedAt:        "2024-01-01T00:00:00.000Z",
				UpdatedAt:        "2024-01-01T00:00:00.000Z",
			},
			{
				Object:           "authorization_resource",
				Id:               "resource_02JF",
				ExternalId:       "my-doc-2",
				Name:             "Second Document",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_01JF",
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
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("returns multiple resources and deserializes response", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, twoItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, twoItemResponse, result)
		require.Equal(t, "resource_01JF", result.Data[0].Id)
		require.Equal(t, "document", result.Data[0].ResourceTypeSlug)
		require.Equal(t, "resource_02JF", result.Data[1].Id)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("returns zero resources", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, emptyResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order desc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Order:                    common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Order:                    common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=asc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Limit:                    25,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=25")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Before:                   "cursor_before",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "before=cursor_before")
		require.NotContains(t, capturedRawQuery, "after=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			After:                    "cursor_after",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "after=cursor_after")
		require.NotContains(t, capturedRawQuery, "before=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes parent resource by ID", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			ParentResourceIdentifier: ParentResourceIdentifierById{
				ParentResourceId: "resource_parent_01",
			},
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "parent_resource_id=resource_parent_01")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes parent resource by external id and type slug", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			ParentResourceIdentifier: ParentResourceIdentifierByExternalId{
				ParentResourceExternalId: "parent-ext-1",
				ParentResourceTypeSlug:   "folder",
			},
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "parent_resource_external_id=parent-ext-1")
		require.Contains(t, capturedRawQuery, "parent_resource_type_slug=folder")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listResourcesServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
			Limit:                    5,
			Before:                   "cursor_before",
			After:                    "cursor_after",
			Order:                    common.Asc,
		})

		require.NoError(t, err)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=5")
		require.Contains(t, capturedRawQuery, "before=cursor_before")
		require.Contains(t, capturedRawQuery, "after=cursor_after")
		require.Contains(t, capturedRawQuery, "order=asc")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		original := DefaultClient
		DefaultClient = &Client{}
		SetAPIKey("")
		defer func() {
			DefaultClient = original
		}()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "API key is required")
	})
}

func TestAuthorizationListMembershipsForResourceWithDefaultClient(t *testing.T) {
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
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("returns multiple memberships and deserializes response", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, twoItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, twoItemResponse, result)
		require.Equal(t, "om_01JF", result.Data[0].Id)
		require.Equal(t, MembershipStatusActive, result.Data[0].Status)
		require.Equal(t, "om_02JF", result.Data[1].Id)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("returns zero memberships", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, emptyResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order desc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Order:          common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Order:          common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=asc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Limit:          25,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=25")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Before:         "cursor_before",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "before=cursor_before")
		require.NotContains(t, capturedRawQuery, "after=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			After:          "cursor_after",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "after=cursor_after")
		require.NotContains(t, capturedRawQuery, "before=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes assignment filter", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
			Assignment:     AssignmentDirect,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "assignment=direct")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
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
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=5")
		require.Contains(t, capturedRawQuery, "before=cursor_before")
		require.Contains(t, capturedRawQuery, "after=cursor_after")
		require.Contains(t, capturedRawQuery, "order=asc")
		require.Contains(t, capturedRawQuery, "assignment=direct")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		original := DefaultClient
		DefaultClient = &Client{}
		SetAPIKey("")
		defer func() {
			DefaultClient = original
		}()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "API key is required")
	})
}

// ---------------------------------------------------------------------------
// Package-level ListMembershipsForResourceByExternalId
// ---------------------------------------------------------------------------

func TestAuthorizationListMembershipsForResourceByExternalIdWithDefaultClient(t *testing.T) {
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

	t.Run("returns one membership", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 1)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("returns multiple memberships and deserializes response", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, twoItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		})

		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, twoItemResponse, result)
		require.Equal(t, "om_01JF", result.Data[0].Id)
		require.Equal(t, "user_01JF", result.Data[0].UserId)
		require.Equal(t, "om_02JF", result.Data[1].Id)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("returns zero memberships", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, emptyResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		})

		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order desc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
			Order:            common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
			Order:            common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=asc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
			Limit:            25,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=25")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
			Before:           "cursor_before",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "before=cursor_before")
		require.NotContains(t, capturedRawQuery, "after=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
			After:            "cursor_after",
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "after=cursor_after")
		require.NotContains(t, capturedRawQuery, "before=")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes assignment filter", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
			Assignment:       AssignmentDirect,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=10")
		require.Contains(t, capturedRawQuery, "order=desc")
		require.Contains(t, capturedRawQuery, "assignment=direct")
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var capturedPath, capturedRawQuery string
		server := listMembershipsExtServer(&capturedPath, &capturedRawQuery, singleItemResponse)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		result, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
			Assignment:       AssignmentDirect,
			Limit:            5,
			Before:           "cursor_before",
			After:            "cursor_after",
			Order:            common.Asc,
		})

		require.NoError(t, err)
		require.Equal(t, singleItemResponse, result)
		require.Equal(t, expectedPath, capturedPath)
		require.Contains(t, capturedRawQuery, "permission_slug=read%3Adocument")
		require.Contains(t, capturedRawQuery, "limit=5")
		require.Contains(t, capturedRawQuery, "before=cursor_before")
		require.Contains(t, capturedRawQuery, "after=cursor_after")
		require.Contains(t, capturedRawQuery, "order=asc")
		require.Contains(t, capturedRawQuery, "assignment=direct")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		})
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		original := DefaultClient
		DefaultClient = &Client{}
		SetAPIKey("")
		defer func() {
			DefaultClient = original
		}()

		_, err := ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
			OrganizationId:   "org_01JF",
			ResourceTypeSlug: "document",
			ExternalId:       "my-doc-1",
			PermissionSlug:   "read:document",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "API key is required")
	})
}

// ---------------------------------------------------------------------------
// SetAPIKey
// ---------------------------------------------------------------------------

func TestSetAPIKey(t *testing.T) {
	original := DefaultClient
	defer func() { DefaultClient = original }()

	DefaultClient = &Client{}
	SetAPIKey("my_key")
	require.Equal(t, "my_key", DefaultClient.APIKey)
}
