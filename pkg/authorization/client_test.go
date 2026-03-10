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

func stringPtr(s string) *string {
	return &s
}

// Create

func TestCreateResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateAuthorizationResourceOpts
		handler  http.HandlerFunc
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			err: true,
		},
		{
			scenario: "Request with both ParentResourceIdentifier and ParentResourceExternalId returns error",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:               "ext_123",
				Name:                     "Test Resource",
				ResourceTypeSlug:         "document",
				OrganizationId:           "org_123",
				ParentResourceIdentifier: ParentResourceIdentifierById{ParentResourceId: "parent_123"},
				ParentResourceExternalId: "parent_ext_123",
				ParentResourceTypeSlug:   "folder",
			},
			err: true,
		},
		{
			scenario: "Request with ParentResourceExternalId but no ParentResourceTypeSlug returns error",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:               "ext_123",
				Name:                     "Test Resource",
				ResourceTypeSlug:         "document",
				OrganizationId:           "org_123",
				ParentResourceExternalId: "parent_ext_123",
			},
			err: true,
		},
		{
			scenario: "Request creates resource with parent by ID",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceIdentifier: ParentResourceIdentifierById{ParentResourceId: "parent_123"},
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: stringPtr("parent_123"),
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource with parent by external ID",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceExternalId: "parent_ext_123",
				ParentResourceTypeSlug:   "folder",
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: stringPtr("parent_123"),
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource without parent",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithoutParentTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource without description",
			client:   &Client{APIKey: "test"},
			handler:  createResourceWithoutDescriptionTestHandler,
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_new",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.CreateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func TestGetResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetAuthorizationResourceOpts
		handler  http.HandlerFunc
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			handler:  getResourceAllFieldsHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			err:      true,
		},
		{
			scenario: "Request returns resource with all fields",
			client:   &Client{APIKey: "test"},
			handler:  getResourceAllFieldsHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      stringPtr("A test resource"),
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: stringPtr("parent_123"),
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request returns resource without parent",
			client:   &Client{APIKey: "test"},
			handler:  getResourceWithoutParentHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      stringPtr("A test resource"),
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: nil,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request returns resource without description",
			client:   &Client{APIKey: "test"},
			handler:  getResourceWithoutDescriptionHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: stringPtr("parent_123"),
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request returns resource without parent and description",
			client:   &Client{APIKey: "test"},
			handler:  getResourceWithoutParentAndDescriptionHandler,
			options:  GetAuthorizationResourceOpts{ResourceId: "resource_123"},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				ParentResourceId: nil,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.GetResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func TestUpdateResource(t *testing.T) {
	newName := "Updated Resource"
	newDesc := "Updated description"

	tests := []struct {
		scenario string
		client   *Client
		options  UpdateAuthorizationResourceOpts
		handler  http.HandlerFunc
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			handler:  updateResourceTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId: "resource_123",
				Name:       &newName,
			},
			err: true,
		},
		{
			scenario: "Updates name and description",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId:  "resource_123",
				Name:        &newName,
				Description: &newDesc,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Updated Resource",
				Description:      stringPtr("Updated description"),
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Updates name only",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceNameOnlyTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId: "resource_123",
				Name:       &newName,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Updated Resource",
				Description:      stringPtr("A test resource"),
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Updates description only",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceDescriptionOnlyTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId:  "resource_123",
				Description: &newDesc,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Test Resource",
				Description:      stringPtr("Updated description"),
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Sets description to null",
			client:   &Client{APIKey: "test"},
			handler:  updateResourceNullDescriptionTestHandler,
			options: UpdateAuthorizationResourceOpts{
				ResourceId: "resource_123",
				Name:       &newName,
				// Description is intentionally left nil (*string zero value).
				// Because the json tag has no omitempty, nil serializes as "description": null,
				// which tells the API to clear the description.
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "resource_123",
				ExternalId:       "ext_123",
				Name:             "Updated Resource",
				Description:      nil,
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.UpdateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

// Delete

func TestDeleteResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteAuthorizationResourceOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			options:  DeleteAuthorizationResourceOpts{ResourceId: "resource_123"},
			err:      true,
		},
		{
			scenario: "Delete without cascade succeeds",
			client:   &Client{APIKey: "test"},
			options: DeleteAuthorizationResourceOpts{
				ResourceId: "resource_123",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteResourceTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeleteResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeleteResourceCascadeQueryParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		cascadeParam := r.URL.Query().Get("cascade_delete")
		require.Equal(t, "true", cascadeParam)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId:    "resource_123",
		CascadeDelete: true,
	})
	require.NoError(t, err)
}

// List

func TestListResources(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListAuthorizationResourcesOpts
		expected ListAuthorizationResourcesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			options:  ListAuthorizationResourcesOpts{},
			err:      true,
		},
		{
			scenario: "Request returns paginated resources",
			client:   &Client{APIKey: "test"},
			options:  ListAuthorizationResourcesOpts{},
			expected: ListAuthorizationResourcesResponse{
				Data: []AuthorizationResource{
					{
						Object:           "authorization_resource",
						Id:               "resource_001",
						ExternalId:       "ext_001",
						Name:             "Resource One",
						Description:      stringPtr("First resource"),
						ResourceTypeSlug: "document",
						OrganizationId:   "org_123",
						ParentResourceId: stringPtr("parent_001"),
						CreatedAt:        "2024-01-01T00:00:00Z",
						UpdatedAt:        "2024-01-01T00:00:00Z",
					},
					{
						Object:           "authorization_resource",
						Id:               "resource_002",
						ExternalId:       "ext_002",
						Name:             "Resource Two",
						Description:      nil,
						ResourceTypeSlug: "document",
						OrganizationId:   "org_123",
						ParentResourceId: nil,
						CreatedAt:        "2024-01-02T00:00:00Z",
						UpdatedAt:        "2024-01-02T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "resource_002",
				},
			},
		},
		{
			scenario: "Request with filters returns filtered resources",
			client:   &Client{APIKey: "test"},
			options: ListAuthorizationResourcesOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
			},
			expected: ListAuthorizationResourcesResponse{
				Data: []AuthorizationResource{
					{
						Object:           "authorization_resource",
						Id:               "resource_001",
						ExternalId:       "ext_001",
						Name:             "Resource One",
						Description:      stringPtr("First resource"),
						ResourceTypeSlug: "document",
						OrganizationId:   "org_123",
						ParentResourceId: stringPtr("parent_001"),
						CreatedAt:        "2024-01-01T00:00:00Z",
						UpdatedAt:        "2024-01-01T00:00:00Z",
					},
					{
						Object:           "authorization_resource",
						Id:               "resource_002",
						ExternalId:       "ext_002",
						Name:             "Resource Two",
						Description:      nil,
						ResourceTypeSlug: "document",
						OrganizationId:   "org_123",
						ParentResourceId: nil,
						CreatedAt:        "2024-01-02T00:00:00Z",
						UpdatedAt:        "2024-01-02T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "resource_002",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listResourcesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resources, err := client.ListResources(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resources)
		})
	}
}

func TestListResourcesFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "org_123", r.URL.Query().Get("organization_id"))
		require.Equal(t, "document", r.URL.Query().Get("resource_type_slug"))

		body, _ := json.Marshal(ListAuthorizationResourcesResponse{
			Data:         []AuthorizationResource{},
			ListMetadata: common.ListMetadata{},
		})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
	})
	require.NoError(t, err)
}

func TestListResourcesDefaultLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		limitParam := r.URL.Query().Get("limit")
		require.Equal(t, "10", limitParam)

		body, _ := json.Marshal(ListAuthorizationResourcesResponse{
			Data:         []AuthorizationResource{},
			ListMetadata: common.ListMetadata{},
		})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{})
	require.NoError(t, err)
}

// Handlers

func createResourceWithParentTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	_, hasParentId := reqBody["parent_resource_id"]
	_, hasParentExtId := reqBody["parent_resource_external_id"]

	if !hasParentId && !hasParentExtId {
		http.Error(w, "expected parent fields in request body", http.StatusBadRequest)
		return
	}

	if hasParentExtId {
		if _, hasTypeSlug := reqBody["parent_resource_type_slug"]; !hasTypeSlug {
			http.Error(w, "parent_resource_type_slug required with parent_resource_external_id", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "authorization_resource",
		"id": "resource_new",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": null,
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": "parent_123",
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`))
}

func createResourceWithoutParentTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if _, hasParentId := reqBody["parent_resource_id"]; hasParentId {
		http.Error(w, "unexpected parent_resource_id in request body", http.StatusBadRequest)
		return
	}
	if _, hasParentExtId := reqBody["parent_resource_external_id"]; hasParentExtId {
		http.Error(w, "unexpected parent_resource_external_id in request body", http.StatusBadRequest)
		return
	}
	if _, hasTypeSlug := reqBody["parent_resource_type_slug"]; hasTypeSlug {
		http.Error(w, "unexpected parent_resource_type_slug in request body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "authorization_resource",
		"id": "resource_new",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": null,
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`))
}

func createResourceWithoutDescriptionTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if _, hasDescription := reqBody["description"]; hasDescription {
		http.Error(w, "unexpected description in request body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "authorization_resource",
		"id": "resource_new",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": null,
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`))
}

func getResourceHandler(w http.ResponseWriter, r *http.Request, responseJSON string) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseJSON))
}

func getResourceAllFieldsHandler(w http.ResponseWriter, r *http.Request) {
	getResourceHandler(w, r, `{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": "A test resource",
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": "parent_123",
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`)
}

func getResourceWithoutParentHandler(w http.ResponseWriter, r *http.Request) {
	getResourceHandler(w, r, `{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": "A test resource",
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`)
}

func getResourceWithoutDescriptionHandler(w http.ResponseWriter, r *http.Request) {
	getResourceHandler(w, r, `{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": null,
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": "parent_123",
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`)
}

func getResourceWithoutParentAndDescriptionHandler(w http.ResponseWriter, r *http.Request) {
	getResourceHandler(w, r, `{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": null,
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z"
	}`)
}

func updateResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Updated Resource",
		"description": "Updated description",
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-02T00:00:00Z"
	}`))
}

func updateResourceNameOnlyTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if _, hasName := reqBody["name"]; !hasName {
		http.Error(w, "expected name in request body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Updated Resource",
		"description": "A test resource",
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-02T00:00:00Z"
	}`))
}

func updateResourceDescriptionOnlyTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if _, hasDesc := reqBody["description"]; !hasDesc {
		http.Error(w, "expected description in request body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Test Resource",
		"description": "Updated description",
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-02T00:00:00Z"
	}`))
}

func updateResourceNullDescriptionTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	descVal, hasDesc := reqBody["description"]
	if !hasDesc {
		http.Error(w, "expected description in request body", http.StatusBadRequest)
		return
	}
	if descVal != nil {
		http.Error(w, "expected description to be null", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "authorization_resource",
		"id": "resource_123",
		"external_id": "ext_123",
		"name": "Updated Resource",
		"description": null,
		"resource_type_slug": "document",
		"organization_id": "org_123",
		"parent_resource_id": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-02T00:00:00Z"
	}`))
}

func deleteResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/authorization/resources/") {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listResourcesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.URL.Path != "/authorization/resources" {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"data": [
			{
				"object": "authorization_resource",
				"id": "resource_001",
				"external_id": "ext_001",
				"name": "Resource One",
				"description": "First resource",
				"resource_type_slug": "document",
				"organization_id": "org_123",
				"parent_resource_id": "parent_001",
				"created_at": "2024-01-01T00:00:00Z",
				"updated_at": "2024-01-01T00:00:00Z"
			},
			{
				"object": "authorization_resource",
				"id": "resource_002",
				"external_id": "ext_002",
				"name": "Resource Two",
				"description": null,
				"resource_type_slug": "document",
				"organization_id": "org_123",
				"parent_resource_id": null,
				"created_at": "2024-01-02T00:00:00Z",
				"updated_at": "2024-01-02T00:00:00Z"
			}
		],
		"list_metadata": {
			"before": "",
			"after": "resource_002"
		}
	}`))
}
