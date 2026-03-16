package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestAuthorizationClientInit(t *testing.T) {
	t.Run("initializes defaults", func(t *testing.T) {
		client := &Client{}
		client.init()

		require.NotNil(t, client.HTTPClient)
		require.Equal(t, "https://api.workos.com", client.Endpoint)
		require.NotNil(t, client.JSONEncode)
	})

	t.Run("preserves existing values", func(t *testing.T) {
		customHTTP := &retryablehttp.HttpClient{}
		client := &Client{
			HTTPClient: customHTTP,
			Endpoint:   "https://custom.endpoint.com",
		}
		client.init()

		require.Equal(t, customHTTP, client.HTTPClient)
		require.Equal(t, "https://custom.endpoint.com", client.Endpoint)
	})
}

func TestAuthorizationClientGetResourceByExternalId(t *testing.T) {
	t.Run("returns resource by external id", func(t *testing.T) {
		var capturedPath string

		response := AuthorizationResource{
			Object:           "authorization_resource",
			Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
			ExternalId:       "my-document-1",
			Name:             "My Document",
			Description:      "A test document",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
			CreatedAt:        "2024-01-01T00:00:00.000Z",
			UpdatedAt:        "2024-01-01T00:00:00.000Z",
		}

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, &capturedPath, response)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
			OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
			ResourceTypeSlug: "document",
			ExternalId:       "my-document-1",
		})

		require.NoError(t, err)
		require.Equal(t, response, result)
		require.Equal(t, "/authorization/organizations/org_01H945H0YD4F97JN3MNHBFPG37/resources/document/my-document-1", capturedPath)
	})

	t.Run("request without api key returns an error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, AuthorizationResource{})))
		defer server.Close()

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}

		_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
			ExternalId:       "ext-1",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "401")
	})
}

func TestAuthorizationClientUpdateResourceByExternalId(t *testing.T) {
	t.Run("updates resource by external id", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		newName := "Updated Document"
		newDescription := "Updated description"

		response := AuthorizationResource{
			Object:           "authorization_resource",
			Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
			ExternalId:       "my-document-1",
			Name:             "Updated Document",
			Description:      "Updated description",
			ResourceTypeSlug: "document",
			OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
			CreatedAt:        "2024-01-01T00:00:00.000Z",
			UpdatedAt:        "2024-01-02T00:00:00.000Z",
		}

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(&capturedBody, &capturedPath, response)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
			OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
			ResourceTypeSlug: "document",
			ExternalId:       "my-document-1",
			Name:             &newName,
			Description:      &newDescription,
		})

		require.NoError(t, err)
		require.Equal(t, response, result)
		require.Equal(t, "/authorization/organizations/org_01H945H0YD4F97JN3MNHBFPG37/resources/document/my-document-1", capturedPath)
		require.Equal(t, "Updated Document", capturedBody["name"])
		require.Equal(t, "Updated description", capturedBody["description"])
	})

	t.Run("request without api key returns an error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, AuthorizationResource{})))
		defer server.Close()

		name := "Test"
		client := &Client{
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
		require.Contains(t, err.Error(), "401")
	})

	t.Run("updates with name and description", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(&capturedBody, &capturedPath, AuthorizationResource{})))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		name := "New Name"
		desc := "New Description"
		_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
			OrganizationId:   "org_abc",
			ResourceTypeSlug: "project",
			ExternalId:       "proj-42",
			Name:             &name,
			Description:      &desc,
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_abc/resources/project/proj-42", capturedPath)
		require.Equal(t, "New Name", capturedBody["name"])
		require.Equal(t, "New Description", capturedBody["description"])
	})

	t.Run("updates only name", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(&capturedBody, nil, AuthorizationResource{})))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		name := "Only Name"
		_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
			ExternalId:       "ext-1",
			Name:             &name,
			Description:      nil,
		})
		require.NoError(t, err)
		require.Equal(t, "Only Name", capturedBody["name"])
		require.NotContains(t, capturedBody, "description")
	})

	t.Run("updates only description", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(&capturedBody, nil, AuthorizationResource{})))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		description := "Only Description"
		_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
			ExternalId:       "ext-1",
			Name:             nil,
			Description:      &description,
		})
		require.NoError(t, err)
		require.NotContains(t, capturedBody, "name")
		require.Equal(t, "Only Description", capturedBody["description"])
	})

	t.Run("returns error on server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		name := "Test"
		_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
			ExternalId:       "ext-1",
			Name:             &name,
		})
		require.Error(t, err)
	})
}

func TestAuthorizationClientDeleteResourceByExternalId(t *testing.T) {
	t.Run("deletes resource by external id", func(t *testing.T) {
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, &capturedPath)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
			OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
			ResourceTypeSlug: "document",
			ExternalId:       "my-document-1",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01H945H0YD4F97JN3MNHBFPG37/resources/document/my-document-1", capturedPath)
	})

	t.Run("request without api key returns an error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, nil)))
		defer server.Close()

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}

		err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
			ExternalId:       "ext-1",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "401")
	})

	t.Run("constructs request without cascade", func(t *testing.T) {
		var capturedPath string
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			capturedRawQuery = r.URL.RawQuery

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
			OrganizationId:   "org_abc",
			ResourceTypeSlug: "project",
			ExternalId:       "proj-42",
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_abc/resources/project/proj-42", capturedPath)
		require.Equal(t, "", capturedRawQuery)
	})

	t.Run("sends cascade_delete query param when true", func(t *testing.T) {
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedRawQuery = r.URL.RawQuery

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
			OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
			ResourceTypeSlug: "document",
			ExternalId:       "my-document-1",
			CascadeDelete:    true,
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "cascade_delete=true")
	})

	t.Run("omits cascade_delete query param when false", func(t *testing.T) {
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedRawQuery = r.URL.RawQuery
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
			ExternalId:       "ext-1",
			CascadeDelete:    false,
		})
		require.NoError(t, err)
		require.Equal(t, "", capturedRawQuery, "No query params when CascadeDelete is false")
	})

	t.Run("returns error on server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "document",
			ExternalId:       "ext-1",
		})
		require.Error(t, err)
	})

	t.Run("url-encodes path segments with special characters", func(t *testing.T) {
		var capturedRawURI string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedRawURI = r.RequestURI
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
			OrganizationId:   "org_123",
			ResourceTypeSlug: "my-type",
			ExternalId:       "ext/with spaces",
		})
		require.NoError(t, err)
		require.Contains(t, capturedRawURI, "/authorization/organizations/org_123/resources/my-type/ext")
		require.Contains(t, capturedRawURI, "%2F")
	})
}

func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

func jsonResponseHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
	response interface{},
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		if capturedBody != nil {
			if err := json.NewDecoder(r.Body).Decode(capturedBody); err != nil {
				http.Error(w, "failed to decode body", http.StatusBadRequest)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}
}

func noContentHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		if capturedBody != nil {
			if err := json.NewDecoder(r.Body).Decode(capturedBody); err != nil {
				http.Error(w, "failed to decode body", http.StatusBadRequest)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
