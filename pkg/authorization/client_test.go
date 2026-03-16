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
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

// ============================================================
// Client initialization tests
// ============================================================

// TestClientInit calls init() directly rather than relying on sync.Once,
// because each test constructs a fresh Client with no prior state.
func TestClientInit(t *testing.T) {
	client := &Client{}
	client.init()

	require.NotNil(t, client.HTTPClient)
	require.Equal(t, "https://api.workos.com", client.Endpoint)
	require.NotNil(t, client.JSONEncode)
}

func TestClientInitPreservesExistingValues(t *testing.T) {
	customHTTP := &retryablehttp.HttpClient{}
	client := &Client{
		HTTPClient: customHTTP,
		Endpoint:   "https://custom.endpoint.com",
	}
	client.init()

	require.Equal(t, customHTTP, client.HTTPClient)
	require.Equal(t, "https://custom.endpoint.com", client.Endpoint)
}

// ============================================================
// GetResourceByExternalId tests
// ============================================================

func TestGetResourceByExternalId(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetResourceByExternalIdOpts
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns resource by external ID",
			client: &Client{
				APIKey: "test",
			},
			options: GetResourceByExternalIdOpts{
				OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
				ResourceTypeSlug: "document",
				ExternalId:       "my-document-1",
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
				ExternalId:       "my-document-1",
				Name:             "My Document",
				Description:      "A test document",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
				CreatedAt:        "2024-01-01T00:00:00.000Z",
				UpdatedAt:        "2024-01-01T00:00:00.000Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getResourceByExternalIdTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.GetResourceByExternalId(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				require.Contains(t, err.Error(), "401")
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func TestGetResourceByExternalIdRequestConstruction(t *testing.T) {
	var capturedReq *http.Request

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthorizationResource{})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test-api-key",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_abc",
		ResourceTypeSlug: "project",
		ExternalId:       "proj-42",
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodGet, capturedReq.Method)
	require.Equal(t, "/authorization/organizations/org_abc/resources/project/proj-42", capturedReq.URL.Path)
	require.Equal(t, "Bearer test-api-key", capturedReq.Header.Get("Authorization"))
	require.Equal(t, "application/json", capturedReq.Header.Get("Content-Type"))
	require.True(t, strings.Contains(capturedReq.Header.Get("User-Agent"), "workos-go/"))
}

func TestGetResourceByExternalIdURLEncoding(t *testing.T) {
	var capturedRawURI string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRawURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthorizationResource{})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	// Path segments with special characters should be URL-encoded
	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "doc-type",
		ExternalId:       "ext/id with spaces",
	})
	require.NoError(t, err)
	require.Contains(t, capturedRawURI, "/authorization/organizations/org_123/resources/doc-type/ext")
	require.Contains(t, capturedRawURI, "%2F")
}

func TestGetResourceByExternalIdServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"internal error"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
	})
	require.Error(t, err)
}

func TestGetResourceByExternalIdNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"not found"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "nonexistent",
	})
	require.Error(t, err)
}

func getResourceByExternalIdTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
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

	expectedPath := "/authorization/organizations/org_01H945H0YD4F97JN3MNHBFPG37/resources/document/my-document-1"
	if r.URL.Path != expectedPath {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	body, err := json.Marshal(AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
		ExternalId:       "my-document-1",
		Name:             "My Document",
		Description:      "A test document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-01T00:00:00.000Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// ============================================================
// UpdateResourceByExternalId tests
// ============================================================

func TestUpdateResourceByExternalId(t *testing.T) {
	newName := "Updated Document"
	newDescription := "Updated description"

	tests := []struct {
		scenario string
		client   *Client
		options  UpdateResourceByExternalIdOpts
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request updates resource by external ID",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateResourceByExternalIdOpts{
				OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
				ResourceTypeSlug: "document",
				ExternalId:       "my-document-1",
				Name:             &newName,
				Description:      &newDescription,
			},
			expected: AuthorizationResource{
				Object:           "authorization_resource",
				Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
				ExternalId:       "my-document-1",
				Name:             "Updated Document",
				Description:      "Updated description",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
				CreatedAt:        "2024-01-01T00:00:00.000Z",
				UpdatedAt:        "2024-01-02T00:00:00.000Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateResourceByExternalIdTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			resource, err := client.UpdateResourceByExternalId(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				require.Contains(t, err.Error(), "401")
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func TestUpdateResourceByExternalIdRequestConstruction(t *testing.T) {
	var capturedReq *http.Request
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthorizationResource{})
	}))
	defer server.Close()

	name := "New Name"
	desc := "New Description"
	client := &Client{
		APIKey:     "test-api-key",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_abc",
		ResourceTypeSlug: "project",
		ExternalId:       "proj-42",
		Name:             &name,
		Description:      &desc,
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodPatch, capturedReq.Method)
	require.Equal(t, "/authorization/organizations/org_abc/resources/project/proj-42", capturedReq.URL.Path)
	require.Equal(t, "Bearer test-api-key", capturedReq.Header.Get("Authorization"))
	require.Equal(t, "application/json", capturedReq.Header.Get("Content-Type"))

	// Verify body contains expected fields
	var bodyMap map[string]interface{}
	err = json.Unmarshal(capturedBody, &bodyMap)
	require.NoError(t, err)
	require.Equal(t, "New Name", bodyMap["name"])
	require.Equal(t, "New Description", bodyMap["description"])
}

func TestUpdateResourceByExternalIdNameOnly(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthorizationResource{})
	}))
	defer server.Close()

	name := "Only Name"
	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		Name:             &name,
		Description:      nil,
	})
	require.NoError(t, err)

	var bodyMap map[string]interface{}
	err = json.Unmarshal(capturedBody, &bodyMap)
	require.NoError(t, err)
	require.Equal(t, "Only Name", bodyMap["name"])
	// Description should be null (present but nil) since the tag has no omitempty
	_, hasDesc := bodyMap["description"]
	require.True(t, hasDesc)
}

func TestUpdateResourceByExternalIdServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message":"validation error"}`))
	}))
	defer server.Close()

	name := "Test"
	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		Name:             &name,
	})
	require.Error(t, err)
}

func updateResourceByExternalIdTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPath := "/authorization/organizations/org_01H945H0YD4F97JN3MNHBFPG37/resources/document/my-document-1"
	if r.URL.Path != expectedPath {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}

	var updateOpts map[string]interface{}
	if err := json.Unmarshal(reqBody, &updateOpts); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if name, ok := updateOpts["name"]; !ok || name != "Updated Document" {
		http.Error(w, "unexpected name in request body", http.StatusBadRequest)
		return
	}
	if desc, ok := updateOpts["description"]; !ok || desc != "Updated description" {
		http.Error(w, "unexpected description in request body", http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
		ExternalId:       "my-document-1",
		Name:             "Updated Document",
		Description:      "Updated description",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-02T00:00:00.000Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// ============================================================
// DeleteResourceByExternalId tests
// ============================================================

func TestDeleteResourceByExternalId(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteResourceByExternalIdOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request deletes resource by external ID",
			client: &Client{
				APIKey: "test",
			},
			options: DeleteResourceByExternalIdOpts{
				OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
				ResourceTypeSlug: "document",
				ExternalId:       "my-document-1",
			},
		},
		{
			scenario: "Request deletes resource by external ID with cascade",
			client: &Client{
				APIKey: "test",
			},
			options: DeleteResourceByExternalIdOpts{
				OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
				ResourceTypeSlug: "document",
				ExternalId:       "my-document-1",
				CascadeDelete:    true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteResourceByExternalIdTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeleteResourceByExternalId(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				require.Contains(t, err.Error(), "401")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeleteResourceByExternalIdRequestConstruction(t *testing.T) {
	var capturedReq *http.Request

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test-api-key",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_abc",
		ResourceTypeSlug: "project",
		ExternalId:       "proj-42",
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodDelete, capturedReq.Method)
	require.Equal(t, "/authorization/organizations/org_abc/resources/project/proj-42", capturedReq.URL.Path)
	require.Equal(t, "Bearer test-api-key", capturedReq.Header.Get("Authorization"))
	require.Equal(t, "", capturedReq.URL.Query().Get("cascade_delete"))
}

func TestDeleteResourceByExternalIdCascadeQueryParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		cascadeDelete := r.URL.Query().Get("cascade_delete")
		if cascadeDelete != "true" {
			http.Error(w, "expected cascade_delete=true", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		ResourceTypeSlug: "document",
		ExternalId:       "my-document-1",
		CascadeDelete:    true,
	})
	require.NoError(t, err)
}

func TestDeleteResourceByExternalIdNoCascadeOmitsParam(t *testing.T) {
	var capturedReq *http.Request

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
		CascadeDelete:    false,
	})
	require.NoError(t, err)
	require.Equal(t, "", capturedReq.URL.RawQuery, "No query params when CascadeDelete is false")
}

func TestDeleteResourceByExternalIdServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "document",
		ExternalId:       "ext-1",
	})
	require.Error(t, err)
}

func TestDeleteResourceByExternalIdURLEncoding(t *testing.T) {
	var capturedRawURI string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRawURI = r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_123",
		ResourceTypeSlug: "my-type",
		ExternalId:       "ext/with spaces",
	})
	require.NoError(t, err)
	require.Contains(t, capturedRawURI, "/authorization/organizations/org_123/resources/my-type/ext")
	require.Contains(t, capturedRawURI, "%2F")
}

func deleteResourceByExternalIdTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPath := "/authorization/organizations/org_01H945H0YD4F97JN3MNHBFPG37/resources/document/my-document-1"
	if r.URL.Path != expectedPath {
		http.Error(w, "invalid path", http.StatusNotFound)
		return
	}

	cascadeDelete := r.URL.Query().Get("cascade_delete")
	if cascadeDelete != "" && cascadeDelete != "true" {
		http.Error(w, "invalid cascade_delete value", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

