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

// setupDefaultClient configures the DefaultClient to point at the given test server
// and returns a cleanup function that restores the original DefaultClient.
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

// ---------------------------------------------------------------------------
// CreateOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationCreateOrganizationRoleWithDefaultClient(t *testing.T) {
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			var opts CreateOrganizationRoleOpts
			json.NewDecoder(r.Body).Decode(&opts)

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
			_ = json.NewEncoder(w).Encode(role)
		}))
	}

	t.Run("creates role and returns OrganizationRole", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		role, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           "Org Admin",
		})

		require.NoError(t, err)
		require.Equal(t, "role_01ABC", role.Id)
		require.Equal(t, "Org Admin", role.Name)
		require.Equal(t, "org-admin", role.Slug)
		require.Equal(t, "OrganizationRole", role.Type)
		require.Equal(t, []string{"read", "write"}, role.Permissions)
	})

	t.Run("sends correct path and method", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           "Org Admin",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01ABC/roles", capturedPath)
		require.Equal(t, http.MethodPost, capturedMethod)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           "Org Admin",
		})

		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// ListOrganizationRoles (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationListOrganizationRolesWithDefaultClient(t *testing.T) {
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			resp := ListOrganizationRolesResponse{
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

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
	}

	t.Run("lists roles and returns ListOrganizationRolesResponse", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		resp, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})

		require.NoError(t, err)
		require.Len(t, resp.Data, 2)
		require.Equal(t, "org-admin", resp.Data[0].Slug)
		require.Equal(t, "org-viewer", resp.Data[1].Slug)
	})

	t.Run("sends correct path and method", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01ABC/roles", capturedPath)
		require.Equal(t, http.MethodGet, capturedMethod)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
			OrganizationId: "org_01ABC",
		})

		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// GetOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationGetOrganizationRoleWithDefaultClient(t *testing.T) {
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			role := OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Admin",
				Slug:        "org-admin",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(role)
		}))
	}

	t.Run("gets role and returns OrganizationRole", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		role, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})

		require.NoError(t, err)
		require.Equal(t, "role_01ABC", role.Id)
		require.Equal(t, "Admin", role.Name)
		require.Equal(t, "org-admin", role.Slug)
	})

	t.Run("sends correct path and method", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01ABC/roles/org-admin", capturedPath)
		require.Equal(t, http.MethodGet, capturedMethod)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		_, err := GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})

		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// UpdateOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationUpdateOrganizationRoleWithDefaultClient(t *testing.T) {
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			var rawBody map[string]json.RawMessage
			json.NewDecoder(r.Body).Decode(&rawBody)

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
			_ = json.NewEncoder(w).Encode(role)
		}))
	}

	t.Run("updates role and returns OrganizationRole", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		name := "Super Admin"
		role, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           &name,
		})

		require.NoError(t, err)
		require.Equal(t, "Super Admin", role.Name)
		require.Equal(t, "2024-01-02T00:00:00Z", role.UpdatedAt)
	})

	t.Run("sends correct path and method", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		name := "Super Admin"
		_, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           &name,
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01ABC/roles/org-admin", capturedPath)
		require.Equal(t, http.MethodPatch, capturedMethod)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		name := "Super Admin"
		_, err := UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
			Name:           &name,
		})

		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// DeleteOrganizationRole (package-level)
// ---------------------------------------------------------------------------

func TestAuthorizationDeleteOrganizationRoleWithDefaultClient(t *testing.T) {
	createServer := func(capturedPath *string, capturedMethod *string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*capturedPath = r.URL.Path
			*capturedMethod = r.Method

			auth := r.Header.Get("Authorization")
			if auth != "Bearer test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		}))
	}

	t.Run("deletes role without error", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})

		require.NoError(t, err)
	})

	t.Run("sends correct path and method", func(t *testing.T) {
		var capturedPath, capturedMethod string
		server := createServer(&capturedPath, &capturedMethod)
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/organizations/org_01ABC/roles/org-admin", capturedPath)
		require.Equal(t, http.MethodDelete, capturedMethod)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		cleanup := setupDefaultClient(server)
		defer cleanup()

		err := DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
			OrganizationId: "org_01ABC",
			Slug:           "org-admin",
		})

		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// SetAPIKey
// ---------------------------------------------------------------------------

func TestSetAPIKey(t *testing.T) {
	original := DefaultClient
	defer func() { DefaultClient = original }()

	DefaultClient = &Client{}
	SetAPIKey("my-api-key")
	require.Equal(t, "my-api-key", DefaultClient.APIKey)
}
