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

// ---------------------------------------------------------------------------
// ListOrganizationRoles
// ---------------------------------------------------------------------------

func TestListOrganizationRoles(t *testing.T) {
	expectedPath := "/authorization/organizations/org_01ABC/roles"

	singleItemResponse := ListOrganizationRolesResponse{
		Data: []OrganizationRole{
			{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Admin",
				Slug:        "org-admin",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
		},
	}

	twoItemResponse := ListOrganizationRolesResponse{
		Data: []OrganizationRole{
			{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Admin",
				Slug:        "org-admin",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
			{
				Object:      "role",
				Id:          "role_02DEF",
				Name:        "Viewer",
				Slug:        "org-viewer",
				Permissions: []string{"read"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-02T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
		},
	}

	emptyResponse := ListOrganizationRolesResponse{
		Data: []OrganizationRole{},
	}

	createServer := func(capturedPath *string, response interface{}) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(nil, capturedPath, response),
		))
	}

	t.Run("returns one role", func(t *testing.T) {
		var cPath string
		server := createServer(&cPath, singleItemResponse)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		result, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, cPath)
		require.Equal(t, singleItemResponse, result)
	})

	t.Run("returns multiple roles and deserializes response", func(t *testing.T) {
		var cPath string
		server := createServer(&cPath, twoItemResponse)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		result, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, cPath)
		require.Equal(t, twoItemResponse, result)
	})

	t.Run("returns zero roles", func(t *testing.T) {
		var cPath string
		server := createServer(&cPath, emptyResponse)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		result, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, cPath)
		require.Equal(t, emptyResponse, result)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// CreateOrganizationRole
// ---------------------------------------------------------------------------

func TestCreateOrganizationRole(t *testing.T) {
	expectedPath := "/authorization/organizations/org_01ABC/roles"

	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	}

	t.Run("creates org role", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, expectedResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		result, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           "Org Admin",
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, capturedPath)
		require.Equal(t, "org-admin", capturedBody["slug"])
		require.Equal(t, "Org Admin", capturedBody["name"])
		require.Equal(t, expectedResponse, result)
	})

	t.Run("creates org role with description", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		desc := "Can manage the organization"
		responseWithDesc := expectedResponse
		responseWithDesc.Description = &desc

		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, responseWithDesc),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		result, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           "Org Admin",
			Description:    "Can manage the organization",
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, capturedPath)
		require.Equal(t, "Can manage the organization", capturedBody["description"])
		require.Equal(t, responseWithDesc, result)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           "Org Admin",
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// GetOrganizationRole
// ---------------------------------------------------------------------------

func TestGetOrganizationRole(t *testing.T) {
	expectedPath := "/authorization/organizations/org_01ABC/roles/org-admin"

	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "org-admin",
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	}

	t.Run("returns organization role", func(t *testing.T) {
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(nil, &capturedPath, expectedResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		result, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, capturedPath)
		require.Equal(t, expectedResponse, result)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// UpdateOrganizationRole
// ---------------------------------------------------------------------------

func TestUpdateOrganizationRole(t *testing.T) {
	expectedPath := "/authorization/organizations/org_01ABC/roles/org-admin"

	expectedResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Super Admin",
		Slug:        "org-admin",
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	}

	t.Run("updates name", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, expectedResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		name := "Super Admin"
		result, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           &name,
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, capturedPath)
		require.Equal(t, "Super Admin", capturedBody["name"])
		require.NotContains(t, capturedBody, "description")
		require.Equal(t, expectedResponse, result)
	})

	t.Run("updates description", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		desc := "Updated description"
		responseWithDesc := expectedResponse
		responseWithDesc.Description = &desc

		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, responseWithDesc),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		result, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Description:    &desc,
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, capturedPath)
		require.Equal(t, "Updated description", capturedBody["description"])
		require.NotContains(t, capturedBody, "name")
		require.Equal(t, responseWithDesc, result)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		name := "Updated"
		_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           &name,
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// DeleteOrganizationRole
// ---------------------------------------------------------------------------

func TestDeleteOrganizationRole(t *testing.T) {
	expectedPath := "/authorization/organizations/org_01ABC/roles/org-admin"

	t.Run("deletes role", func(t *testing.T) {
		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(
			noContentHandler(nil, &capturedPath),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.NoError(t, err)
		require.Equal(t, expectedPath, capturedPath)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

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
