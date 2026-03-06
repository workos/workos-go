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

	// Validate query parameters
	q := r.URL.Query()
	if q.Get("permission_slug") != "read:document" {
		http.Error(w, "expected permission_slug=read:document", http.StatusBadRequest)
		return
	}
	if q.Get("limit") != "10" {
		http.Error(w, "expected limit=10", http.StatusBadRequest)
		return
	}
	if q.Get("order") != "desc" {
		http.Error(w, "expected order=desc", http.StatusBadRequest)
		return
	}
	if q.Get("OrganizationMembershipId") != "" {
		http.Error(w, "OrganizationMembershipId must not appear in query string", http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListAuthorizationResourcesResponse{
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
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

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

	// Validate query parameters
	q := r.URL.Query()
	if q.Get("permission_slug") != "read:document" {
		http.Error(w, "expected permission_slug=read:document", http.StatusBadRequest)
		return
	}
	if q.Get("limit") != "10" {
		http.Error(w, "expected limit=10", http.StatusBadRequest)
		return
	}
	if q.Get("order") != "desc" {
		http.Error(w, "expected order=desc", http.StatusBadRequest)
		return
	}
	if q.Get("ResourceId") != "" {
		http.Error(w, "ResourceId must not appear in query string", http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListAuthorizationOrganizationMembershipsResponse{
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
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

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
}

func listMembershipsForResourceByExternalIdTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	// Validate path: /authorization/organizations/{orgId}/resources/{typeSlug}/{externalId}/organization_memberships
	if !strings.HasPrefix(r.URL.Path, "/authorization/organizations/") ||
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

	// Validate query parameters
	q := r.URL.Query()
	if q.Get("permission_slug") != "read:document" {
		http.Error(w, "expected permission_slug=read:document", http.StatusBadRequest)
		return
	}
	if q.Get("limit") != "10" {
		http.Error(w, "expected limit=10", http.StatusBadRequest)
		return
	}
	if q.Get("order") != "desc" {
		http.Error(w, "expected order=desc", http.StatusBadRequest)
		return
	}
	if q.Get("OrganizationId") != "" {
		http.Error(w, "OrganizationId must not appear in query string", http.StatusBadRequest)
		return
	}
	if q.Get("ResourceTypeSlug") != "" {
		http.Error(w, "ResourceTypeSlug must not appear in query string", http.StatusBadRequest)
		return
	}
	if q.Get("ExternalId") != "" {
		http.Error(w, "ExternalId must not appear in query string", http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListAuthorizationOrganizationMembershipsResponse{
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
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
