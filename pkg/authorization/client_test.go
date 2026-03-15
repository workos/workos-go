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

// ---------------------------------------------------------------------------
// ListResourcesForMembership
// ---------------------------------------------------------------------------

func TestListResourcesForMembership(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListResourcesForMembershipOpts
		expected ListAuthorizationResourcesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns resources accessible by membership",
			client: &Client{
				APIKey: "test",
			},
			options: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01JF",
				PermissionSlug:           "read:document",
			},
			expected: ListAuthorizationResourcesResponse{
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
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
		{
			scenario: "Request with parent resource by ID includes parent_resource_id in query",
			client: &Client{
				APIKey: "test",
			},
			options: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01JF",
				PermissionSlug:           "read:document",
				ParentResource: ParentResourceIdentifierById{
					ParentResourceId: "resource_parent_01",
				},
			},
			expected: ListAuthorizationResourcesResponse{
				Data: []AuthorizationResource{
					{
						Object:           "authorization_resource",
						Id:               "resource_01JF",
						ExternalId:       "my-doc-1",
						Name:             "My Document",
						Description:      "A test document",
						ResourceTypeSlug: "document",
						OrganizationId:   "org_01JF",
						ParentResourceId: "resource_parent_01",
						CreatedAt:        "2024-01-01T00:00:00.000Z",
						UpdatedAt:        "2024-01-01T00:00:00.000Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
		{
			scenario: "Request with parent resource by external ID includes parent external params in query",
			client: &Client{
				APIKey: "test",
			},
			options: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01JF",
				PermissionSlug:           "read:document",
				ParentResource: ParentResourceIdentifierByExternalId{
					ParentResourceExternalId: "parent-ext-1",
					ParentResourceTypeSlug:   "folder",
				},
			},
			expected: ListAuthorizationResourcesResponse{
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
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
		{
			scenario: "Request with pagination parameters",
			client: &Client{
				APIKey: "test",
			},
			options: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01JF",
				PermissionSlug:           "read:document",
				Limit:                    5,
				After:                    "cursor_abc",
				Order:                    common.Asc,
			},
			expected: ListAuthorizationResourcesResponse{
				Data: []AuthorizationResource{
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
				ListMetadata: common.ListMetadata{
					Before: "cursor_abc",
					After:  "cursor_def",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listResourcesForMembershipTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			response, err := client.ListResourcesForMembership(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}

	// Capture-based subtests for query parameter verification
	captureServer := func(capturedPath *string, capturedRawQuery *string, response ListAuthorizationResourcesResponse) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedRawQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
		}))
	}

	singleResponse := ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{{
			Object: "authorization_resource", Id: "resource_01JF",
			ExternalId: "my-doc-1", Name: "My Document",
			ResourceTypeSlug: "document", OrganizationId: "org_01JF",
			CreatedAt: "2024-01-01T00:00:00.000Z", UpdatedAt: "2024-01-01T00:00:00.000Z",
		}},
		ListMetadata: common.ListMetadata{After: "resource_01JF"},
	}

	twoResponse := ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{
			{Object: "authorization_resource", Id: "resource_01JF", ResourceTypeSlug: "document",
				CreatedAt: "2024-01-01T00:00:00.000Z", UpdatedAt: "2024-01-01T00:00:00.000Z"},
			{Object: "authorization_resource", Id: "resource_02JF", ResourceTypeSlug: "document",
				CreatedAt: "2024-01-02T00:00:00.000Z", UpdatedAt: "2024-01-02T00:00:00.000Z"},
		},
		ListMetadata: common.ListMetadata{After: "resource_02JF"},
	}

	emptyResponse := ListAuthorizationResourcesResponse{
		Data: []AuthorizationResource{}, ListMetadata: common.ListMetadata{},
	}

	expectedPath := "/authorization/organization_memberships/om_01JF/resources"

	t.Run("returns multiple resources and deserializes response", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, twoResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, "resource_01JF", result.Data[0].Id)
		require.Equal(t, "resource_02JF", result.Data[1].Id)
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("returns zero resources", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, emptyResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document", Order: common.Asc,
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "order=asc")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "limit=10")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document", Limit: 25,
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "limit=25")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document", Before: "cursor_before",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "before=cursor_before")
		require.NotContains(t, cQuery, "after=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document", After: "cursor_after",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "after=cursor_after")
		require.NotContains(t, cQuery, "before=")
		require.Equal(t, expectedPath, cPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleResponse)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document",
			Limit: 5, Before: "cursor_before", After: "cursor_after", Order: common.Asc,
		})
		require.NoError(t, err)
		require.Equal(t, singleResponse, result)
		require.Equal(t, expectedPath, cPath)
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
			OrganizationMembershipId: "om_01JF", PermissionSlug: "read:document",
		})
		require.Error(t, err)
	})
}

func listResourcesForMembershipTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/organization_memberships/") ||
		!strings.HasSuffix(r.URL.Path, "/resources") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verify path-only fields do not leak into query string
	q := r.URL.Query()
	if q.Get("OrganizationMembershipId") != "" {
		http.Error(w, "OrganizationMembershipId must not appear in query string", http.StatusBadRequest)
		return
	}

	// Branch response based on query params to support multiple test scenarios
	if q.Get("parent_resource_id") == "resource_parent_01" {
		writeJSON(w, ListAuthorizationResourcesResponse{
			Data: []AuthorizationResource{
				{
					Object:           "authorization_resource",
					Id:               "resource_01JF",
					ExternalId:       "my-doc-1",
					Name:             "My Document",
					Description:      "A test document",
					ResourceTypeSlug: "document",
					OrganizationId:   "org_01JF",
					ParentResourceId: "resource_parent_01",
					CreatedAt:        "2024-01-01T00:00:00.000Z",
					UpdatedAt:        "2024-01-01T00:00:00.000Z",
				},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
		return
	}

	if q.Get("parent_resource_external_id") == "parent-ext-1" {
		if q.Get("parent_resource_type_slug") != "folder" {
			http.Error(w, "expected parent_resource_type_slug=folder", http.StatusBadRequest)
			return
		}
		writeJSON(w, ListAuthorizationResourcesResponse{
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
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
		return
	}

	if q.Get("after") == "cursor_abc" {
		if q.Get("limit") != "5" {
			http.Error(w, "expected limit=5", http.StatusBadRequest)
			return
		}
		if q.Get("order") != "asc" {
			http.Error(w, "expected order=asc", http.StatusBadRequest)
			return
		}
		writeJSON(w, ListAuthorizationResourcesResponse{
			Data: []AuthorizationResource{
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
			ListMetadata: common.ListMetadata{Before: "cursor_abc", After: "cursor_def"},
		})
		return
	}

	// Default response: validate default limit and order
	if q.Get("permission_slug") != "read:document" {
		http.Error(w, "expected permission_slug=read:document", http.StatusBadRequest)
		return
	}
	if q.Get("limit") != "10" {
		http.Error(w, "expected default limit=10", http.StatusBadRequest)
		return
	}
	if q.Get("order") != "desc" {
		http.Error(w, "expected default order=desc", http.StatusBadRequest)
		return
	}

	writeJSON(w, ListAuthorizationResourcesResponse{
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
		ListMetadata: common.ListMetadata{Before: "", After: ""},
	})
}

// ---------------------------------------------------------------------------
// ListMembershipsForResource
// ---------------------------------------------------------------------------

func TestListMembershipsForResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListMembershipsForResourceOpts
		expected ListAuthorizationOrganizationMembershipsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns memberships that have the permission on the resource",
			client: &Client{
				APIKey: "test",
			},
			options: ListMembershipsForResourceOpts{
				ResourceId:     "resource_01JF",
				PermissionSlug: "read:document",
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object:         "organization_membership",
						Id:             "om_01JF",
						UserId:         "user_01JF",
						OrganizationId: "org_01JF",
						Status:         "active",
						CreatedAt:      "2024-01-01T00:00:00.000Z",
						UpdatedAt:      "2024-01-01T00:00:00.000Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
		{
			scenario: "Request with assignment filter",
			client: &Client{
				APIKey: "test",
			},
			options: ListMembershipsForResourceOpts{
				ResourceId:     "resource_01JF",
				PermissionSlug: "read:document",
				Assignment:     "direct",
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object:         "organization_membership",
						Id:             "om_02JF",
						UserId:         "user_02JF",
						OrganizationId: "org_01JF",
						Status:         "active",
						CreatedAt:      "2024-01-02T00:00:00.000Z",
						UpdatedAt:      "2024-01-02T00:00:00.000Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
		{
			scenario: "Request with custom pagination",
			client: &Client{
				APIKey: "test",
			},
			options: ListMembershipsForResourceOpts{
				ResourceId:     "resource_01JF",
				PermissionSlug: "read:document",
				Limit:          5,
				After:          "cursor_abc",
				Order:          common.Asc,
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object:         "organization_membership",
						Id:             "om_03JF",
						UserId:         "user_03JF",
						OrganizationId: "org_01JF",
						Status:         "active",
						CreatedAt:      "2024-01-03T00:00:00.000Z",
						UpdatedAt:      "2024-01-03T00:00:00.000Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "cursor_abc",
					After:  "cursor_def",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listMembershipsForResourceTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			response, err := client.ListMembershipsForResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}

	// Capture-based subtests for query parameter verification
	captureServer := func(capturedPath *string, capturedRawQuery *string, response ListAuthorizationOrganizationMembershipsResponse) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedRawQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
		}))
	}

	singleMembership := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{{
			Object: "organization_membership", Id: "om_01JF",
			UserId: "user_01JF", OrganizationId: "org_01JF", Status: "active",
			CreatedAt: "2024-01-01T00:00:00.000Z", UpdatedAt: "2024-01-01T00:00:00.000Z",
		}},
		ListMetadata: common.ListMetadata{After: "om_01JF"},
	}

	twoMemberships := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{Object: "organization_membership", Id: "om_01JF", UserId: "user_01JF",
				OrganizationId: "org_01JF", Status: "active",
				CreatedAt: "2024-01-01T00:00:00.000Z", UpdatedAt: "2024-01-01T00:00:00.000Z"},
			{Object: "organization_membership", Id: "om_02JF", UserId: "user_02JF",
				OrganizationId: "org_01JF", Status: "active",
				CreatedAt: "2024-01-02T00:00:00.000Z", UpdatedAt: "2024-01-02T00:00:00.000Z"},
		},
		ListMetadata: common.ListMetadata{After: "om_02JF"},
	}

	emptyMemberships := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{}, ListMetadata: common.ListMetadata{},
	}

	expectedMembershipPath := "/authorization/resources/resource_01JF/organization_memberships"

	t.Run("returns multiple memberships and deserializes response", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, twoMemberships)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, "om_01JF", result.Data[0].Id)
		require.Equal(t, "om_02JF", result.Data[1].Id)
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("returns zero memberships", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, emptyMemberships)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document", Order: common.Asc,
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "order=asc")
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "limit=10")
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document", Limit: 25,
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "limit=25")
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document", Before: "cursor_before",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "before=cursor_before")
		require.NotContains(t, cQuery, "after=")
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document", After: "cursor_after",
		})
		require.NoError(t, err)
		require.Contains(t, cQuery, "after=cursor_after")
		require.NotContains(t, cQuery, "before=")
		require.Equal(t, expectedMembershipPath, cPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var cPath, cQuery string
		server := captureServer(&cPath, &cQuery, singleMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
			ResourceId: "resource_01JF", PermissionSlug: "read:document",
			Assignment: "direct", Limit: 5, Before: "cursor_before", After: "cursor_after", Order: common.Asc,
		})
		require.NoError(t, err)
		require.Equal(t, singleMembership, result)
		require.Equal(t, expectedMembershipPath, cPath)
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
			ResourceId: "resource_01JF", PermissionSlug: "read:document",
		})
		require.Error(t, err)
	})
}

func listMembershipsForResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") ||
		!strings.HasSuffix(r.URL.Path, "/organization_memberships") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	q := r.URL.Query()

	// Verify path-only fields do not leak into query string
	if q.Get("ResourceId") != "" {
		http.Error(w, "ResourceId must not appear in query string", http.StatusBadRequest)
		return
	}

	// Branch by assignment filter
	if q.Get("assignment") == "direct" {
		writeJSON(w, ListAuthorizationOrganizationMembershipsResponse{
			Data: []AuthorizationOrganizationMembership{
				{
					Object:         "organization_membership",
					Id:             "om_02JF",
					UserId:         "user_02JF",
					OrganizationId: "org_01JF",
					Status:         "active",
					CreatedAt:      "2024-01-02T00:00:00.000Z",
					UpdatedAt:      "2024-01-02T00:00:00.000Z",
				},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
		return
	}

	// Branch by pagination
	if q.Get("after") == "cursor_abc" {
		if q.Get("limit") != "5" {
			http.Error(w, "expected limit=5", http.StatusBadRequest)
			return
		}
		if q.Get("order") != "asc" {
			http.Error(w, "expected order=asc", http.StatusBadRequest)
			return
		}
		writeJSON(w, ListAuthorizationOrganizationMembershipsResponse{
			Data: []AuthorizationOrganizationMembership{
				{
					Object:         "organization_membership",
					Id:             "om_03JF",
					UserId:         "user_03JF",
					OrganizationId: "org_01JF",
					Status:         "active",
					CreatedAt:      "2024-01-03T00:00:00.000Z",
					UpdatedAt:      "2024-01-03T00:00:00.000Z",
				},
			},
			ListMetadata: common.ListMetadata{Before: "cursor_abc", After: "cursor_def"},
		})
		return
	}

	// Default response with default limit/order validation
	if q.Get("permission_slug") != "read:document" {
		http.Error(w, "expected permission_slug=read:document", http.StatusBadRequest)
		return
	}
	if q.Get("limit") != "10" {
		http.Error(w, "expected default limit=10", http.StatusBadRequest)
		return
	}
	if q.Get("order") != "desc" {
		http.Error(w, "expected default order=desc", http.StatusBadRequest)
		return
	}

	writeJSON(w, ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{
				Object:         "organization_membership",
				Id:             "om_01JF",
				UserId:         "user_01JF",
				OrganizationId: "org_01JF",
				Status:         "active",
				CreatedAt:      "2024-01-01T00:00:00.000Z",
				UpdatedAt:      "2024-01-01T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{Before: "", After: ""},
	})
}

// ---------------------------------------------------------------------------
// ListMembershipsForResourceByExternalId
// ---------------------------------------------------------------------------

func TestListMembershipsForResourceByExternalId(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListMembershipsForResourceByExternalIdOpts
		expected ListAuthorizationOrganizationMembershipsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns memberships by external resource ID",
			client: &Client{
				APIKey: "test",
			},
			options: ListMembershipsForResourceByExternalIdOpts{
				OrganizationId:   "org_01JF",
				ResourceTypeSlug: "document",
				ExternalId:       "my-doc-1",
				PermissionSlug:   "read:document",
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object:         "organization_membership",
						Id:             "om_01JF",
						UserId:         "user_01JF",
						OrganizationId: "org_01JF",
						Status:         "active",
						CreatedAt:      "2024-01-01T00:00:00.000Z",
						UpdatedAt:      "2024-01-01T00:00:00.000Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
		{
			scenario: "Request with assignment filter and custom pagination",
			client: &Client{
				APIKey: "test",
			},
			options: ListMembershipsForResourceByExternalIdOpts{
				OrganizationId:   "org_01JF",
				ResourceTypeSlug: "document",
				ExternalId:       "my-doc-1",
				PermissionSlug:   "read:document",
				Assignment:       "direct",
				Limit:            5,
				After:            "cursor_abc",
				Order:            common.Asc,
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object:         "organization_membership",
						Id:             "om_04JF",
						UserId:         "user_04JF",
						OrganizationId: "org_01JF",
						Status:         "active",
						CreatedAt:      "2024-01-04T00:00:00.000Z",
						UpdatedAt:      "2024-01-04T00:00:00.000Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "cursor_abc",
					After:  "cursor_def",
				},
			},
		},
		{
			scenario: "Request constructs correct URL path with org, type, and external ID segments",
			client: &Client{
				APIKey: "test",
			},
			options: ListMembershipsForResourceByExternalIdOpts{
				OrganizationId:   "org_99",
				ResourceTypeSlug: "project",
				ExternalId:       "proj-42",
				PermissionSlug:   "manage:project",
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object:         "organization_membership",
						Id:             "om_05JF",
						UserId:         "user_05JF",
						OrganizationId: "org_99",
						Status:         "active",
						CreatedAt:      "2024-02-01T00:00:00.000Z",
						UpdatedAt:      "2024-02-01T00:00:00.000Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listMembershipsForResourceByExternalIdTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			response, err := client.ListMembershipsForResourceByExternalId(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}

	// Capture-based subtests for query parameter verification
	captureExtServer := func(capturedPath *string, capturedRawQuery *string, response ListAuthorizationOrganizationMembershipsResponse) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedRawQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
		}))
	}

	singleExtMembership := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{{
			Object: "organization_membership", Id: "om_01JF",
			UserId: "user_01JF", OrganizationId: "org_01JF", Status: "active",
			CreatedAt: "2024-01-01T00:00:00.000Z", UpdatedAt: "2024-01-01T00:00:00.000Z",
		}},
		ListMetadata: common.ListMetadata{After: "om_01JF"},
	}

	twoExtMemberships := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{Object: "organization_membership", Id: "om_01JF", UserId: "user_01JF",
				OrganizationId: "org_01JF", Status: "active",
				CreatedAt: "2024-01-01T00:00:00.000Z", UpdatedAt: "2024-01-01T00:00:00.000Z"},
			{Object: "organization_membership", Id: "om_02JF", UserId: "user_02JF",
				OrganizationId: "org_01JF", Status: "active",
				CreatedAt: "2024-01-02T00:00:00.000Z", UpdatedAt: "2024-01-02T00:00:00.000Z"},
		},
		ListMetadata: common.ListMetadata{After: "om_02JF"},
	}

	emptyExtMemberships := ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{}, ListMetadata: common.ListMetadata{},
	}

	expectedExtPath := "/authorization/organizations/org_01JF/resources/document/my-doc-1/organization_memberships"

	baseExtOpts := func() ListMembershipsForResourceByExternalIdOpts {
		return ListMembershipsForResourceByExternalIdOpts{
			OrganizationId: "org_01JF", ResourceTypeSlug: "document",
			ExternalId: "my-doc-1", PermissionSlug: "read:document",
		}
	}

	t.Run("returns multiple memberships and deserializes response", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, twoExtMemberships)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseExtOpts())
		require.NoError(t, err)
		require.Len(t, result.Data, 2)
		require.Equal(t, "om_01JF", result.Data[0].Id)
		require.Equal(t, "om_02JF", result.Data[1].Id)
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("returns zero memberships", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, emptyExtMemberships)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		result, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseExtOpts())
		require.NoError(t, err)
		require.Empty(t, result.Data)
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("applies default order when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, singleExtMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseExtOpts())
		require.NoError(t, err)
		require.Contains(t, cQuery, "order=desc")
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("passes order asc", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, singleExtMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		opts := baseExtOpts()
		opts.Order = common.Asc
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)
		require.NoError(t, err)
		require.Contains(t, cQuery, "order=asc")
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, singleExtMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseExtOpts())
		require.NoError(t, err)
		require.Contains(t, cQuery, "limit=10")
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, singleExtMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		opts := baseExtOpts()
		opts.Limit = 25
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)
		require.NoError(t, err)
		require.Contains(t, cQuery, "limit=25")
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, singleExtMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		opts := baseExtOpts()
		opts.Before = "cursor_before"
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)
		require.NoError(t, err)
		require.Contains(t, cQuery, "before=cursor_before")
		require.NotContains(t, cQuery, "after=")
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, singleExtMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		opts := baseExtOpts()
		opts.After = "cursor_after"
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)
		require.NoError(t, err)
		require.Contains(t, cQuery, "after=cursor_after")
		require.NotContains(t, cQuery, "before=")
		require.Equal(t, expectedExtPath, cPath)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var cPath, cQuery string
		server := captureExtServer(&cPath, &cQuery, singleExtMembership)
		defer server.Close()
		client := newAuthorizationTestClient(server)
		opts := baseExtOpts()
		opts.Assignment = "direct"
		opts.Limit = 5
		opts.Before = "cursor_before"
		opts.After = "cursor_after"
		opts.Order = common.Asc
		result, err := client.ListMembershipsForResourceByExternalId(context.Background(), opts)
		require.NoError(t, err)
		require.Equal(t, singleExtMembership, result)
		require.Equal(t, expectedExtPath, cPath)
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
		_, err := client.ListMembershipsForResourceByExternalId(context.Background(), baseExtOpts())
		require.Error(t, err)
	})
}

func listMembershipsForResourceByExternalIdTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	// Validate path structure:
	// /authorization/organizations/{orgId}/resources/{typeSlug}/{externalId}/organization_memberships
	if !strings.HasPrefix(r.URL.Path, "/authorization/organizations/") ||
		!strings.HasSuffix(r.URL.Path, "/organization_memberships") {
		http.Error(w, "invalid path prefix or suffix", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verify path-only fields do not leak into query string
	q := r.URL.Query()
	for _, forbidden := range []string{"OrganizationId", "ResourceTypeSlug", "ExternalId"} {
		if q.Get(forbidden) != "" {
			http.Error(w, forbidden+" must not appear in query string", http.StatusBadRequest)
			return
		}
	}

	// Extract path segments to validate URL construction
	// Path: /authorization/organizations/{orgId}/resources/{typeSlug}/{externalId}/organization_memberships
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Expected: authorization, organizations, {orgId}, resources, {typeSlug}, {externalId}, organization_memberships
	if len(segments) != 7 {
		http.Error(w, "unexpected path segment count", http.StatusBadRequest)
		return
	}
	orgId := segments[2]
	typeSlug := segments[4]
	externalId := segments[5]

	// Scenario: different org/type/external for URL construction test
	if orgId == "org_99" && typeSlug == "project" && externalId == "proj-42" {
		writeJSON(w, ListAuthorizationOrganizationMembershipsResponse{
			Data: []AuthorizationOrganizationMembership{
				{
					Object:         "organization_membership",
					Id:             "om_05JF",
					UserId:         "user_05JF",
					OrganizationId: "org_99",
					Status:         "active",
					CreatedAt:      "2024-02-01T00:00:00.000Z",
					UpdatedAt:      "2024-02-01T00:00:00.000Z",
				},
			},
			ListMetadata: common.ListMetadata{Before: "", After: ""},
		})
		return
	}

	// Scenario: assignment + pagination
	if q.Get("assignment") == "direct" && q.Get("after") == "cursor_abc" {
		if q.Get("limit") != "5" {
			http.Error(w, "expected limit=5", http.StatusBadRequest)
			return
		}
		if q.Get("order") != "asc" {
			http.Error(w, "expected order=asc", http.StatusBadRequest)
			return
		}
		writeJSON(w, ListAuthorizationOrganizationMembershipsResponse{
			Data: []AuthorizationOrganizationMembership{
				{
					Object:         "organization_membership",
					Id:             "om_04JF",
					UserId:         "user_04JF",
					OrganizationId: "org_01JF",
					Status:         "active",
					CreatedAt:      "2024-01-04T00:00:00.000Z",
					UpdatedAt:      "2024-01-04T00:00:00.000Z",
				},
			},
			ListMetadata: common.ListMetadata{Before: "cursor_abc", After: "cursor_def"},
		})
		return
	}

	// Default response with default limit/order validation
	if q.Get("permission_slug") != "read:document" {
		http.Error(w, "expected permission_slug=read:document", http.StatusBadRequest)
		return
	}
	if q.Get("limit") != "10" {
		http.Error(w, "expected default limit=10", http.StatusBadRequest)
		return
	}
	if q.Get("order") != "desc" {
		http.Error(w, "expected default order=desc", http.StatusBadRequest)
		return
	}

	writeJSON(w, ListAuthorizationOrganizationMembershipsResponse{
		Data: []AuthorizationOrganizationMembership{
			{
				Object:         "organization_membership",
				Id:             "om_01JF",
				UserId:         "user_01JF",
				OrganizationId: "org_01JF",
				Status:         "active",
				CreatedAt:      "2024-01-01T00:00:00.000Z",
				UpdatedAt:      "2024-01-01T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{Before: "", After: ""},
	})
}

// ---------------------------------------------------------------------------
// Stub method tests -- verify all stubs return "not implemented"
// These ensure the method signatures compile and the stubs behave correctly.
// When a stub is implemented, its test should be expanded to full coverage.
// ---------------------------------------------------------------------------

func TestCreateEnvironmentRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateEnvironmentRoleOpts
		err      bool
	}{
		{
			scenario: "Stub returns not implemented",
			client:   &Client{APIKey: "test"},
			options: CreateEnvironmentRoleOpts{
				Slug: "admin",
				Name: "Admin",
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			_, err := test.client.CreateEnvironmentRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				require.Contains(t, err.Error(), "not implemented")
			}
		})
	}
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
	name := "Updated Admin"
	client := &Client{APIKey: "test"}
	_, err := client.UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug: "admin",
		Name: &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreateOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		Name:           "Editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListOrganizationRoles(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateOrganizationRole(t *testing.T) {
	name := "Updated Editor"
	client := &Client{APIKey: "test"}
	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		Name:           &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestSetEnvironmentRolePermissions(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read:doc", "write:doc"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddEnvironmentRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "delete:doc",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestSetOrganizationRolePermissions(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		Permissions:    []string{"read:doc"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddOrganizationRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		PermissionSlug: "write:doc",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveOrganizationRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_01",
		Slug:           "editor",
		PermissionSlug: "write:doc",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreatePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "read:doc",
		Name: "Read Document",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListPermissions(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
		Limit: 10,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetPermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetPermission(context.Background(), GetPermissionOpts{Slug: "read:doc"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdatePermission(t *testing.T) {
	name := "Updated Read"
	client := &Client{APIKey: "test"}
	_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "read:doc",
		Name: &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeletePermission(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.DeletePermission(context.Background(), DeletePermissionOpts{Slug: "read:doc"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetResource(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{
		ResourceId: "resource_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreateResource(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext-1",
		Name:             "Test Resource",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateResource(t *testing.T) {
	name := "Updated Resource"
	client := &Client{APIKey: "test"}
	_, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId: "resource_01",
		Name:       &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResource(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId: "resource_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListResources(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
		OrganizationId:   "org_01",
		ResourceTypeSlug: "document",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateResourceByExternalId(t *testing.T) {
	name := "Updated"
	client := &Client{APIKey: "test"}
	_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		Name:             &name,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCheck(t *testing.T) {
	client := &Client{APIKey: "test"}

	t.Run("Stub returns not implemented with ResourceIdentifierById", func(t *testing.T) {
		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01",
			PermissionSlug:           "read:document",
			Resource: ResourceIdentifierById{
				ResourceId: "resource_01",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})

	t.Run("Stub returns not implemented with ResourceIdentifierByExternalId", func(t *testing.T) {
		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01",
			PermissionSlug:           "read:document",
			Resource: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext-1",
				ResourceTypeSlug:   "document",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})
}

func TestListRoleAssignments(t *testing.T) {
	client := &Client{APIKey: "test"}
	_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01",
		Limit:                    10,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAssignRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	t.Run("Stub returns not implemented with ResourceIdentifierById", func(t *testing.T) {
		_, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01",
			RoleSlug:                 "admin",
			ResourceIdentifier: ResourceIdentifierById{
				ResourceId: "resource_01",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})

	t.Run("Stub returns not implemented with ResourceIdentifierByExternalId", func(t *testing.T) {
		_, err := client.AssignRole(context.Background(), AssignRoleOpts{
			OrganizationMembershipId: "om_01",
			RoleSlug:                 "admin",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext-1",
				ResourceTypeSlug:   "document",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})
}

func TestRemoveRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	t.Run("Stub returns not implemented with ResourceIdentifierById", func(t *testing.T) {
		err := client.RemoveRole(context.Background(), RemoveRoleOpts{
			OrganizationMembershipId: "om_01",
			RoleSlug:                 "admin",
			ResourceIdentifier: ResourceIdentifierById{
				ResourceId: "resource_01",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})
}

func TestRemoveRoleAssignment(t *testing.T) {
	client := &Client{APIKey: "test"}
	err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01",
		RoleAssignmentId:         "ra_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	body, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
