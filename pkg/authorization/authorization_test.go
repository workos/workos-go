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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		original := DefaultClient
		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("")
		defer func() {
			DefaultClient = original
		}()

		_, err := ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF",
			PermissionSlug:           "read:document",
		})
		require.Error(t, err)
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		original := DefaultClient
		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
		SetAPIKey("")
		defer func() {
			DefaultClient = original
		}()

		_, err := ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId:     "resource_01JF",
			PermissionSlug: "read:document",
		})
		require.Error(t, err)
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		original := DefaultClient
		DefaultClient = &Client{
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
			Endpoint:   server.URL,
		}
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
	})
}

// ---------------------------------------------------------------------------
// Package-level stub wrappers -- verify delegation to DefaultClient.
// Each test uses setupDefaultClient so that when stubs are implemented with
// real HTTP calls, requests will hit the test server instead of production.
// ---------------------------------------------------------------------------

// stubTestServer returns a no-op test server suitable for stub tests that
// return "not implemented" before making any HTTP call.
func stubTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unexpected call to stub server", http.StatusInternalServerError)
	}))
}

func TestAuthorizationCreateEnvironmentRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "admin",
		Name: "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListEnvironmentRoles(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetEnvironmentRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateEnvironmentRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	name := "Updated Admin"
	_, err := UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug: "admin",
		Name: &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCreateOrganizationRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		Name:           "Editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListOrganizationRoles(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetOrganizationRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateOrganizationRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	name := "Updated Editor"
	_, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		Name:           &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteOrganizationRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationSetEnvironmentRolePermissions(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read:doc", "write:doc"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddEnvironmentRolePermission(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "delete:doc",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationSetOrganizationRolePermissions(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		Permissions:    []string{"read:doc"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAddOrganizationRolePermission(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		PermissionSlug: "write:doc",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveOrganizationRolePermission(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	err := RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		PermissionSlug: "write:doc",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCreatePermission(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "read:doc",
		Name: "Read Document",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListPermissions(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := ListPermissions(context.Background(), ListPermissionsOpts{Limit: 10})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetPermission(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := GetPermission(context.Background(), GetPermissionOpts{Slug: "read:doc"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdatePermission(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	name := "Updated Read"
	_, err := UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "read:doc",
		Name: &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeletePermission(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	err := DeletePermission(context.Background(), DeletePermissionOpts{Slug: "read:doc"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetResource(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "resource_01"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCreateResource(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext-1",
		Name:             "Test",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateResource(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	name := "Updated"
	_, err := UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId: "resource_01",
		Name:       &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteResource(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	err := DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "resource_01"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListResources(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := ListResources(context.Background(), ListAuthorizationResourcesOpts{
		OrganizationId: "org_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationGetResourceByExternalId(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationUpdateResourceByExternalId(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	name := "Updated"
	_, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		Name:             &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationDeleteResourceByExternalId(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	err := DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationCheck(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01",
		PermissionSlug:           "read:document",
		Resource: ResourceIdentifierById{
			ResourceId: "resource_01",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationListRoleAssignments(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationAssignRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	_, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01",
		RoleSlug:                 "admin",
		ResourceIdentifier: ResourceIdentifierById{
			ResourceId: "resource_01",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRole(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01",
		RoleSlug:                 "admin",
		ResourceIdentifier: ResourceIdentifierById{
			ResourceId: "resource_01",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	server := stubTestServer()
	defer server.Close()
	cleanup := setupDefaultClient(server)
	defer cleanup()

	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01",
		RoleAssignmentId:         "ra_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
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
