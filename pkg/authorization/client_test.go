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
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
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
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
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
				return
			}
			require.NoError(t, err)
		})
	}
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
