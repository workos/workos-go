package authorization

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestListRoleAssignments(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListRoleAssignmentsOpts
		expected ListRoleAssignmentsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns paginated role assignments",
			client: &Client{
				APIKey: "test",
			},
			options: ListRoleAssignmentsOpts{
				OrganizationMembershipId: "om_01JKR3PB",
				Limit:                    10,
			},
			expected: ListRoleAssignmentsResponse{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listRoleAssignmentsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			result, err := client.ListRoleAssignments(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
}

func listRoleAssignmentsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organization_memberships/om_01JKR3PB/role_assignments") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, err := json.Marshal(ListRoleAssignmentsResponse{
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
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestAssignRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AssignRoleOpts
		expected RoleAssignment
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Assign role with resource by ID",
			client: &Client{
				APIKey: "test",
			},
			options: AssignRoleOpts{
				OrganizationMembershipId: "om_01JKR3PB",
				RoleSlug:                 "admin",
				Resource:                 ResourceIdentifierById{ResourceId: "resource_01"},
			},
			expected: RoleAssignment{
				Object: "role_assignment",
				Id:     "ra_01ABC",
				Role:   RoleAssignmentRole{Slug: "admin"},
				Resource: RoleAssignmentResource{
					Id:               "resource_01",
					ResourceTypeSlug: "project",
				},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(assignRoleTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			result, err := client.AssignRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
}

func assignRoleTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	expectedPath := "/authorization/organization_memberships/om_01JKR3PB/role_assignments"
	if r.URL.Path != expectedPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var reqBody map[string]interface{}
	json.NewDecoder(r.Body).Decode(&reqBody)

	if reqBody["role_slug"] != "admin" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if reqBody["resource_id"] != "resource_01" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_01ABC",
		Role:   RoleAssignmentRole{Slug: "admin"},
		Resource: RoleAssignmentResource{
			Id:               "resource_01",
			ResourceTypeSlug: "project",
		},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestRemoveRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  RemoveRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Remove role with resource by ID sends DELETE with JSON body",
			client: &Client{
				APIKey: "test",
			},
			options: RemoveRoleOpts{
				OrganizationMembershipId: "om_01JKR3PB",
				RoleSlug:                 "admin",
				Resource:                 ResourceIdentifierById{ResourceId: "resource_01"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(removeRoleTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.RemoveRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func removeRoleTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Verify DELETE request has a JSON body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil || len(bodyBytes) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var reqBody map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if reqBody["role_slug"] != "admin" || reqBody["resource_id"] != "resource_01" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func TestRemoveRoleAssignment(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  RemoveRoleAssignmentOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Successful removal returns nil error",
			client: &Client{
				APIKey: "test",
			},
			options: RemoveRoleAssignmentOpts{
				OrganizationMembershipId: "om_01JKR3PB",
				RoleAssignmentId:         "ra_01ABC",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(removeRoleAssignmentTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.RemoveRoleAssignment(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func removeRoleAssignmentTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Verify both path parameters are present
	expectedPath := "/authorization/organization_memberships/om_01JKR3PB/role_assignments/ra_01ABC"
	if r.URL.Path != expectedPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func TestAssignRoleWithExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(assignRoleExternalIdTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	result, err := client.AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "editor",
		Resource: ResourceIdentifierByExternalId{
			ResourceExternalId: "ext-resource-42",
			ResourceTypeSlug:   "document",
		},
	})

	require.NoError(t, err)
	require.Equal(t, RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_03GHI",
		Role:   RoleAssignmentRole{Slug: "editor"},
		Resource: RoleAssignmentResource{
			ExternalId:       "ext-resource-42",
			ResourceTypeSlug: "document",
		},
		CreatedAt: "2024-01-03T00:00:00Z",
		UpdatedAt: "2024-01-03T00:00:00Z",
	}, result)
}

func assignRoleExternalIdTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	expectedPath := "/authorization/organization_memberships/om_01JKR3PB/role_assignments"
	if r.URL.Path != expectedPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var reqBody map[string]interface{}
	json.NewDecoder(r.Body).Decode(&reqBody)

	if reqBody["role_slug"] != "editor" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if reqBody["resource_external_id"] != "ext-resource-42" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if reqBody["resource_type_slug"] != "document" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verify resource_id is NOT present when using external ID
	if _, exists := reqBody["resource_id"]; exists {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_03GHI",
		Role:   RoleAssignmentRole{Slug: "editor"},
		Resource: RoleAssignmentResource{
			ExternalId:       "ext-resource-42",
			ResourceTypeSlug: "document",
		},
		CreatedAt: "2024-01-03T00:00:00Z",
		UpdatedAt: "2024-01-03T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestRemoveRoleWithExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(removeRoleExternalIdTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "editor",
		Resource: ResourceIdentifierByExternalId{
			ResourceExternalId: "ext-resource-42",
			ResourceTypeSlug:   "document",
		},
	})

	require.NoError(t, err)
}

func removeRoleExternalIdTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	expectedPath := "/authorization/organization_memberships/om_01JKR3PB/role_assignments"
	if r.URL.Path != expectedPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil || len(bodyBytes) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var reqBody map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if reqBody["role_slug"] != "editor" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if reqBody["resource_external_id"] != "ext-resource-42" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if reqBody["resource_type_slug"] != "document" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, exists := reqBody["resource_id"]; exists {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
