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

// stringPtr returns a pointer to the given string, used for optional update fields.
func stringPtr(s string) *string {
	return &s
}

// newAuthorizationTestClient creates a Client wired to the given test server.
func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

// ---------------------------------------------------------------------------
// CreateOrganizationRole
// ---------------------------------------------------------------------------

func TestCreateOrganizationRole(t *testing.T) {
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var opts CreateOrganizationRoleOpts
			json.NewDecoder(r.Body).Decode(&opts)

			if opts.Slug == "" || opts.Name == "" {
				http.Error(w, "slug and name are required", http.StatusBadRequest)
				return
			}

			var desc *string
			if opts.Description != "" {
				desc = &opts.Description
			}
			role := OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        opts.Name,
				Slug:        opts.Slug,
				Description: desc,
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(role)
		}))
	}

	t.Run("creates org role and returns OrganizationRole", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		role, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           "Org Admin",
		})
		require.NoError(t, err)
		require.Equal(t, "role_01ABC", role.Id)
		require.Equal(t, "Org Admin", role.Name)
		require.Equal(t, "org-admin", role.Slug)
		require.Nil(t, role.Description)
		require.Equal(t, []string{"read", "write"}, role.Permissions)
		require.Equal(t, "OrganizationRole", role.Type)
	})

	t.Run("with description includes it in the response", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		role, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-editor",
			Name:           "Org Editor",
			Description:    "Can edit things",
		})
		require.NoError(t, err)
		require.Equal(t, "Org Editor", role.Name)
		require.Equal(t, "org-editor", role.Slug)
		require.NotNil(t, role.Description)
		require.Equal(t, "Can edit things", *role.Description)
	})

	t.Run("sends correct path", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01XYZ",
			Slug:           "admin",
			Name:           "Admin",
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles", path)
		require.Equal(t, http.MethodPost, method)
	})

	t.Run("omits optional fields from request body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			bodyStr := string(bodyBytes)
			require.NotContains(t, bodyStr, `"description"`,
				"serialized body must omit description when empty (omitempty)")

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"Viewer","slug":"org-viewer","description":"","permissions":["read"],"resource_type_slug":"","type":"OrganizationRole","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-viewer",
			Name:           "Viewer",
		})
		require.NoError(t, err)
	})

	t.Run("returns error on 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Organization not found"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_nonexistent",
			Slug:           "admin",
			Name:           "Admin",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "404")
	})

	t.Run("returns error on 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"Internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "admin",
			Name:           "Admin",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "500")
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{not valid json`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "admin",
			Name:           "Admin",
		})
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}
		_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "admin",
			Name:           "Admin",
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// ListOrganizationRoles
// ---------------------------------------------------------------------------

func TestListOrganizationRoles(t *testing.T) {
	listResponse := ListOrganizationRolesResponse{
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

	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(listResponse)
		}))
	}

	t.Run("returns list of roles for the organization", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		roles, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.NoError(t, err)
		require.Len(t, roles.Data, 2)
		require.Equal(t, "role_01ABC", roles.Data[0].Id)
		require.Equal(t, "role_02DEF", roles.Data[1].Id)
	})

	t.Run("uses GET method and sends correct path", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01ABC/roles", path)
		require.Equal(t, http.MethodGet, method)
	})

	t.Run("returns empty list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":[]}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		resp, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.NoError(t, err)
		require.Empty(t, resp.Data)
	})

	t.Run("returns error on 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Organization not found"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_nonexistent",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "404")
	})

	t.Run("returns error on 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"Internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "500")
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}
		_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// GetOrganizationRole
// ---------------------------------------------------------------------------

func TestGetOrganizationRole(t *testing.T) {
	roleResponse := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "org-admin",
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	}

	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(roleResponse)
		}))
	}

	t.Run("returns OrganizationRole by org ID and slug", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		role, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.NoError(t, err)
		require.Equal(t, "role_01ABC", role.Id)
		require.Equal(t, "Admin", role.Name)
		require.Equal(t, "org-admin", role.Slug)
		require.Equal(t, []string{"read", "write"}, role.Permissions)
	})

	t.Run("sends correct path and method", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01XYZ",
			Slug:           "my-role",
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles/my-role", path)
		require.Equal(t, http.MethodGet, method)
	})

	t.Run("returns error on 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Role not found"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "nonexistent-role",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "404")
	})

	t.Run("returns error on 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"Internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "500")
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{not valid json`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.Error(t, err)
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}
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
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			var rawBody map[string]json.RawMessage
			if err := json.Unmarshal(bodyBytes, &rawBody); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			role := OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Slug:        "org-admin",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			}

			if nameRaw, ok := rawBody["name"]; ok {
				var name string
				json.Unmarshal(nameRaw, &name)
				role.Name = name
			}

			if descRaw, ok := rawBody["description"]; ok {
				if string(descRaw) == "null" {
					role.Description = nil
				} else {
					var desc string
					json.Unmarshal(descRaw, &desc)
					role.Description = &desc
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(role)
		}))
	}

	t.Run("updates name", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		role, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           stringPtr("Super Admin"),
		})
		require.NoError(t, err)
		require.Equal(t, "Super Admin", role.Name)
		require.Equal(t, http.MethodPatch, method)
	})

	t.Run("sets description to null", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		role, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Description:    nil,
		})
		require.NoError(t, err)
		require.Nil(t, role.Description)
	})

	t.Run("updates description only", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		role, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Description:    stringPtr("New description"),
		})
		require.NoError(t, err)
		require.NotNil(t, role.Description)
		require.Equal(t, "New description", *role.Description)
	})

	t.Run("sends correct path", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01XYZ",
			Slug:           "editor",
			Name:           stringPtr("Editor"),
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles/editor", path)
		require.Equal(t, http.MethodPatch, method)
	})

	t.Run("null description body serialization", func(t *testing.T) {
		// Verifies that a nil *string Description always serializes as
		// "description":null in the JSON body. Go's encoding/json cannot
		// distinguish between "field was not provided" and "field was
		// explicitly set to null" when using a pointer type without omitempty.
		// This is an accepted trade-off: every PATCH request will include
		// "description":null when the caller does not set Description.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}

			bodyStr := string(bodyBytes)
			require.Contains(t, bodyStr, `"description":null`,
				"serialized body must contain description:null when Description pointer is nil")
			require.NotContains(t, bodyStr, `"name"`,
				"serialized body must omit name when Name pointer is nil")

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"","slug":"org-admin","description":"","permissions":[],"resource_type_slug":"","type":"OrganizationRole","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-02T00:00:00Z"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Description:    nil,
		})
		require.NoError(t, err)
	})

	t.Run("returns error on 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Role not found"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "nonexistent-role",
			Name:           stringPtr("Updated"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "404")
	})

	t.Run("returns error on 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"Internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           stringPtr("Updated"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "500")
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}
		_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           stringPtr("Updated"),
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// DeleteOrganizationRole
// ---------------------------------------------------------------------------

func TestDeleteOrganizationRole(t *testing.T) {
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		}))
	}

	t.Run("successful delete returns nil error", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.NoError(t, err)
	})

	t.Run("sends correct path and method", func(t *testing.T) {
		var path, method string
		server := createServer(&path, &method)
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01XYZ",
			Slug:           "viewer",
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles/viewer", path)
		require.Equal(t, http.MethodDelete, method)
	})

	t.Run("returns error on 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Role not found"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "nonexistent-role",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "404")
	})

	t.Run("returns error on 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"Internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "500")
	})

	t.Run("Request without API Key returns an error", func(t *testing.T) {
		client := &Client{}
		err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// ResourceIdentifier interface tests
// ---------------------------------------------------------------------------

func TestResourceIdentifierByIdParams(t *testing.T) {
	r := ResourceIdentifierById{ResourceId: "res_01ABC"}
	params := r.resourceIdentifierParams()
	require.Equal(t, "res_01ABC", params["resource_id"])
	require.Len(t, params, 1)
}

func TestResourceIdentifierByExternalIdParams(t *testing.T) {
	r := ResourceIdentifierByExternalId{
		ResourceExternalId: "ext_01",
		ResourceTypeSlug:   "document",
	}
	params := r.resourceIdentifierParams()
	require.Equal(t, "ext_01", params["resource_external_id"])
	require.Equal(t, "document", params["resource_type_slug"])
	require.Len(t, params, 2)
}

func TestParentResourceIdentifierByIdParams(t *testing.T) {
	r := ParentResourceIdentifierById{ParentResourceId: "res_parent_01"}
	params := r.parentResourceIdentifierParams()
	require.Equal(t, "res_parent_01", params["parent_resource_id"])
	require.Len(t, params, 1)
}

func TestParentResourceIdentifierByExternalIdParams(t *testing.T) {
	r := ParentResourceIdentifierByExternalId{
		ParentResourceExternalId: "ext_parent_01",
		ParentResourceTypeSlug:   "folder",
	}
	params := r.parentResourceIdentifierParams()
	require.Equal(t, "ext_parent_01", params["parent_resource_external_id"])
	require.Equal(t, "folder", params["parent_resource_type_slug"])
	require.Len(t, params, 2)
}

// ---------------------------------------------------------------------------
// Client init tests
// ---------------------------------------------------------------------------

func TestClientInitDefaults(t *testing.T) {
	client := &Client{}
	client.init()

	require.NotNil(t, client.HTTPClient)
	require.Equal(t, "https://api.workos.com", client.Endpoint)
	require.NotNil(t, client.JSONEncode)
}

func TestClientInitPreservesCustomValues(t *testing.T) {
	customHTTPClient := &retryablehttp.HttpClient{}
	customEndpoint := "https://custom.endpoint.com"

	client := &Client{
		HTTPClient: customHTTPClient,
		Endpoint:   customEndpoint,
	}
	client.init()

	require.Equal(t, customHTTPClient, client.HTTPClient)
	require.Equal(t, customEndpoint, client.Endpoint)
}
