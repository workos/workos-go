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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func stringPtr(s string) *string {
	return &s
}

// newTestClient creates a Client wired to the given test server.
func newTestClient(server *httptest.Server, apiKey string) *Client {
	return &Client{
		APIKey:     apiKey,
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

// authGuard validates Bearer token and User-Agent. Returns false and writes
// an error response when validation fails so the caller can return early.
func authGuard(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	if ua := r.Header.Get("User-Agent"); !strings.Contains(ua, "workos-go/") {
		http.Error(w, "missing user-agent", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

// ---------------------------------------------------------------------------
// Environment Roles
// ---------------------------------------------------------------------------

func TestCreateEnvironmentRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateEnvironmentRoleOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request creates role and returns EnvironmentRole",
			client:   &Client{APIKey: "test"},
			options: CreateEnvironmentRoleOpts{
				Slug: "admin",
				Name: "Admin",
			},
			expected: EnvironmentRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Admin",
				Slug:        "admin",
				Description: "",
				Permissions: []string{"read", "write"},
				Type:        "environment",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request with ResourceTypeSlug sends it in JSON body",
			client:   &Client{APIKey: "test"},
			options: CreateEnvironmentRoleOpts{
				Slug:             "doc-admin",
				Name:             "Document Admin",
				ResourceTypeSlug: "document",
			},
			expected: EnvironmentRole{
				Object:           "role",
				Id:               "role_01ABC",
				Name:             "Document Admin",
				Slug:             "doc-admin",
				Permissions:      []string{"read", "write"},
				ResourceTypeSlug: "document",
				Type:             "environment",
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createEnvironmentRoleTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.CreateEnvironmentRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func createEnvironmentRoleTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authGuard(w, r) {
		return
	}

	var opts CreateEnvironmentRoleOpts
	json.NewDecoder(r.Body).Decode(&opts)

	if opts.Slug == "" || opts.Name == "" {
		http.Error(w, "slug and name are required", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, EnvironmentRole{
		Object:           "role",
		Id:               "role_01ABC",
		Name:             opts.Name,
		Slug:             opts.Slug,
		Description:      opts.Description,
		Permissions:      []string{"read", "write"},
		ResourceTypeSlug: opts.ResourceTypeSlug,
		Type:             "environment",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	})
}

func TestCreateEnvironmentRoleOmitsOptionalFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		bodyStr := string(bodyBytes)
		require.NotContains(t, bodyStr, `"description"`,
			"serialized body must omit description when empty (omitempty)")
		require.NotContains(t, bodyStr, `"resource_type_slug"`,
			"serialized body must omit resource_type_slug when empty (omitempty)")

		writeJSON(w, http.StatusOK, EnvironmentRole{
			Object: "role", Id: "role_01ABC", Name: "Viewer", Slug: "viewer",
			Permissions: []string{"read"}, Type: "environment",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "viewer",
		Name: "Viewer",
	})
	require.NoError(t, err)
}

func TestListEnvironmentRoles(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		expected ListEnvironmentRolesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns list of EnvironmentRoles",
			client:   &Client{APIKey: "test"},
			expected: ListEnvironmentRolesResponse{
				Data: []EnvironmentRole{
					{
						Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
						Permissions: []string{"read", "write"}, Type: "environment",
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
					{
						Object: "role", Id: "role_02DEF", Name: "Viewer", Slug: "viewer",
						Permissions: []string{"read"}, Type: "environment",
						CreatedAt: "2024-01-02T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listEnvironmentRolesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			roles, err := client.ListEnvironmentRoles(context.Background())
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, roles)
		})
	}
}

func listEnvironmentRolesTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authGuard(w, r) {
		return
	}

	writeJSON(w, http.StatusOK, ListEnvironmentRolesResponse{
		Data: []EnvironmentRole{
			{
				Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
				Permissions: []string{"read", "write"}, Type: "environment",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
			{
				Object: "role", Id: "role_02DEF", Name: "Viewer", Slug: "viewer",
				Permissions: []string{"read"}, Type: "environment",
				CreatedAt: "2024-01-02T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
	})
}

func TestGetEnvironmentRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetEnvironmentRoleOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns EnvironmentRole by slug",
			client:   &Client{APIKey: "test"},
			options:  GetEnvironmentRoleOpts{Slug: "admin"},
			expected: EnvironmentRole{
				Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
				Permissions: []string{"read", "write"}, Type: "environment",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getEnvironmentRoleTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.GetEnvironmentRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func getEnvironmentRoleTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authGuard(w, r) {
		return
	}

	if !strings.HasSuffix(r.URL.Path, "/admin") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, EnvironmentRole{
		Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
		Permissions: []string{"read", "write"}, Type: "environment",
		CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
	})
}

func TestUpdateEnvironmentRole(t *testing.T) {
	updatedName := "Super Admin"

	tests := []struct {
		scenario string
		client   *Client
		options  UpdateEnvironmentRoleOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request uses PATCH method and updates name",
			client:   &Client{APIKey: "test"},
			options:  UpdateEnvironmentRoleOpts{Slug: "admin", Name: &updatedName},
			expected: EnvironmentRole{
				Object: "role", Id: "role_01ABC", Name: "Super Admin", Slug: "admin",
				Permissions: []string{"read", "write"}, Type: "environment",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Request sets description to null",
			client:   &Client{APIKey: "test"},
			options:  UpdateEnvironmentRoleOpts{Slug: "admin", Description: nil},
			expected: EnvironmentRole{
				Object: "role", Id: "role_01ABC", Slug: "admin",
				Permissions: []string{"read", "write"}, Type: "environment",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Request updates description only",
			client:   &Client{APIKey: "test"},
			options:  UpdateEnvironmentRoleOpts{Slug: "admin", Description: stringPtr("New description")},
			expected: EnvironmentRole{
				Object: "role", Id: "role_01ABC", Slug: "admin", Description: "New description",
				Permissions: []string{"read", "write"}, Type: "environment",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateEnvironmentRoleTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.UpdateEnvironmentRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func updateEnvironmentRoleTestHandler(w http.ResponseWriter, r *http.Request) {
	if !authGuard(w, r) {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

	role := EnvironmentRole{
		Object: "role", Id: "role_01ABC", Slug: "admin",
		Permissions: []string{"read", "write"}, Type: "environment",
		CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
	}

	if nameRaw, ok := rawBody["name"]; ok {
		var name string
		json.Unmarshal(nameRaw, &name)
		role.Name = name
	}

	if descRaw, ok := rawBody["description"]; ok {
		if string(descRaw) == "null" {
			role.Description = ""
		} else {
			var desc string
			json.Unmarshal(descRaw, &desc)
			role.Description = desc
		}
	}

	writeJSON(w, http.StatusOK, role)
}

func TestUpdateEnvironmentRoleNullDescriptionBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodyStr := string(bodyBytes)
		require.Contains(t, bodyStr, `"description":null`)
		require.NotContains(t, bodyStr, `"name"`)

		writeJSON(w, http.StatusOK, EnvironmentRole{
			Object: "role", Id: "role_01ABC", Slug: "admin",
			Permissions: []string{}, Type: "environment",
			CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
		})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug:        "admin",
		Description: nil,
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Environment Role Permissions
// ---------------------------------------------------------------------------

func TestSetEnvironmentRolePermissions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SetEnvironmentRolePermissionsOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request sets permissions via PUT and returns updated role",
			client:   &Client{APIKey: "test"},
			options: SetEnvironmentRolePermissionsOpts{
				Slug:        "admin",
				Permissions: []string{"read", "write", "delete"},
			},
			expected: EnvironmentRole{
				Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
				Permissions: []string{"read", "write", "delete"}, Type: "environment",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPut, r.Method)
				require.True(t, strings.HasSuffix(r.URL.Path, "/permissions"))

				var opts SetEnvironmentRolePermissionsOpts
				json.NewDecoder(r.Body).Decode(&opts)

				writeJSON(w, http.StatusOK, EnvironmentRole{
					Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
					Permissions: opts.Permissions, Type: "environment",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.SetEnvironmentRolePermissions(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func TestAddEnvironmentRolePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AddEnvironmentRolePermissionOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request adds permission via POST and returns updated role",
			client:   &Client{APIKey: "test"},
			options: AddEnvironmentRolePermissionOpts{
				Slug:           "admin",
				PermissionSlug: "delete",
			},
			expected: EnvironmentRole{
				Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
				Permissions: []string{"read", "write", "delete"}, Type: "environment",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPost, r.Method)

				writeJSON(w, http.StatusOK, EnvironmentRole{
					Object: "role", Id: "role_01ABC", Name: "Admin", Slug: "admin",
					Permissions: []string{"read", "write", "delete"}, Type: "environment",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.AddEnvironmentRolePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

// ---------------------------------------------------------------------------
// Organization Roles
// ---------------------------------------------------------------------------

func TestCreateOrganizationRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateOrganizationRoleOpts
		expected OrganizationRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request creates organization role",
			client:   &Client{APIKey: "test"},
			options: CreateOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "editor",
				Name:           "Editor",
				Description:    "Can edit content",
			},
			expected: OrganizationRole{
				Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
				Description: "Can edit content", Permissions: []string{"read", "write"},
				Type: "organization", CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/roles", r.URL.Path)

				var opts CreateOrganizationRoleOpts
				json.NewDecoder(r.Body).Decode(&opts)

				writeJSON(w, http.StatusOK, OrganizationRole{
					Object: "role", Id: "role_01ABC", Name: opts.Name, Slug: opts.Slug,
					Description: opts.Description, Permissions: []string{"read", "write"},
					Type: "organization", CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.CreateOrganizationRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func TestListOrganizationRoles(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListOrganizationRolesOpts
		expected ListOrganizationRolesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns list of organization roles",
			client:   &Client{APIKey: "test"},
			options:  ListOrganizationRolesOpts{OrganizationId: "org_01ABC"},
			expected: ListOrganizationRolesResponse{
				Data: []OrganizationRole{
					{
						Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
						Permissions: []string{"read", "write"}, Type: "organization",
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/roles", r.URL.Path)

				writeJSON(w, http.StatusOK, ListOrganizationRolesResponse{
					Data: []OrganizationRole{
						{
							Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
							Permissions: []string{"read", "write"}, Type: "organization",
							CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
						},
					},
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			roles, err := client.ListOrganizationRoles(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, roles)
		})
	}
}

func TestGetOrganizationRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetOrganizationRoleOpts
		expected OrganizationRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns organization role by slug",
			client:   &Client{APIKey: "test"},
			options:  GetOrganizationRoleOpts{OrganizationId: "org_01ABC", Slug: "editor"},
			expected: OrganizationRole{
				Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
				Permissions: []string{"read", "write"}, Type: "organization",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/roles/editor", r.URL.Path)

				writeJSON(w, http.StatusOK, OrganizationRole{
					Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
					Permissions: []string{"read", "write"}, Type: "organization",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.GetOrganizationRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func TestUpdateOrganizationRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdateOrganizationRoleOpts
		expected OrganizationRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request updates organization role via PATCH",
			client:   &Client{APIKey: "test"},
			options: UpdateOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "editor",
				Name:           stringPtr("Senior Editor"),
			},
			expected: OrganizationRole{
				Object: "role", Id: "role_01ABC", Name: "Senior Editor", Slug: "editor",
				Permissions: []string{"read", "write"}, Type: "organization",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPatch, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/roles/editor", r.URL.Path)

				bodyBytes, _ := io.ReadAll(r.Body)
				var rawBody map[string]json.RawMessage
				json.Unmarshal(bodyBytes, &rawBody)

				role := OrganizationRole{
					Object: "role", Id: "role_01ABC", Slug: "editor",
					Permissions: []string{"read", "write"}, Type: "organization",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
				}
				if nameRaw, ok := rawBody["name"]; ok {
					var name string
					json.Unmarshal(nameRaw, &name)
					role.Name = name
				}

				writeJSON(w, http.StatusOK, role)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.UpdateOrganizationRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func TestDeleteOrganizationRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteOrganizationRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request deletes organization role",
			client:   &Client{APIKey: "test"},
			options:  DeleteOrganizationRoleOpts{OrganizationId: "org_01ABC", Slug: "editor"},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodDelete, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/roles/editor", r.URL.Path)

				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeleteOrganizationRole(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Organization Role Permissions
// ---------------------------------------------------------------------------

func TestSetOrganizationRolePermissions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SetOrganizationRolePermissionsOpts
		expected OrganizationRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request sets permissions via PUT",
			client:   &Client{APIKey: "test"},
			options: SetOrganizationRolePermissionsOpts{
				OrganizationId: "org_01ABC",
				Slug:           "editor",
				Permissions:    []string{"read", "write"},
			},
			expected: OrganizationRole{
				Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
				Permissions: []string{"read", "write"}, Type: "organization",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPut, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/roles/editor/permissions", r.URL.Path)

				var opts SetOrganizationRolePermissionsOpts
				json.NewDecoder(r.Body).Decode(&opts)

				writeJSON(w, http.StatusOK, OrganizationRole{
					Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
					Permissions: opts.Permissions, Type: "organization",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.SetOrganizationRolePermissions(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func TestAddOrganizationRolePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AddOrganizationRolePermissionOpts
		expected OrganizationRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request adds permission via POST",
			client:   &Client{APIKey: "test"},
			options: AddOrganizationRolePermissionOpts{
				OrganizationId: "org_01ABC",
				Slug:           "editor",
				PermissionSlug: "delete",
			},
			expected: OrganizationRole{
				Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
				Permissions: []string{"read", "write", "delete"}, Type: "organization",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPost, r.Method)

				writeJSON(w, http.StatusOK, OrganizationRole{
					Object: "role", Id: "role_01ABC", Name: "Editor", Slug: "editor",
					Permissions: []string{"read", "write", "delete"}, Type: "organization",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.AddOrganizationRolePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func TestRemoveOrganizationRolePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  RemoveOrganizationRolePermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request removes permission via DELETE",
			client:   &Client{APIKey: "test"},
			options: RemoveOrganizationRolePermissionOpts{
				OrganizationId: "org_01ABC",
				Slug:           "editor",
				PermissionSlug: "delete",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodDelete, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/roles/editor/permissions/delete", r.URL.Path)

				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.RemoveOrganizationRolePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

func TestCreatePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreatePermissionOpts
		expected Permission
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request creates permission",
			client:   &Client{APIKey: "test"},
			options: CreatePermissionOpts{
				Slug: "read",
				Name: "Read",
			},
			expected: Permission{
				Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates permission with resource type slug",
			client:   &Client{APIKey: "test"},
			options: CreatePermissionOpts{
				Slug:             "doc-read",
				Name:             "Document Read",
				ResourceTypeSlug: "document",
			},
			expected: Permission{
				Object: "permission", Id: "perm_01ABC", Slug: "doc-read", Name: "Document Read",
				ResourceTypeSlug: "document",
				CreatedAt:        "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPost, r.Method)

				var opts CreatePermissionOpts
				json.NewDecoder(r.Body).Decode(&opts)

				writeJSON(w, http.StatusOK, Permission{
					Object: "permission", Id: "perm_01ABC", Slug: opts.Slug, Name: opts.Name,
					Description: opts.Description, ResourceTypeSlug: opts.ResourceTypeSlug,
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			perm, err := client.CreatePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, perm)
		})
	}
}

func TestListPermissions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListPermissionsOpts
		expected ListPermissionsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns list of permissions",
			client:   &Client{APIKey: "test"},
			options:  ListPermissionsOpts{},
			expected: ListPermissionsResponse{
				Data: []Permission{
					{
						Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read",
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{Before: "", After: ""},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)

				writeJSON(w, http.StatusOK, ListPermissionsResponse{
					Data: []Permission{
						{
							Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read",
							CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
						},
					},
					ListMetadata: common.ListMetadata{Before: "", After: ""},
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			perms, err := client.ListPermissions(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, perms)
		})
	}
}

func TestGetPermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetPermissionOpts
		expected Permission
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns permission by slug",
			client:   &Client{APIKey: "test"},
			options:  GetPermissionOpts{Slug: "read"},
			expected: Permission{
				Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.True(t, strings.HasSuffix(r.URL.Path, "/read"))

				writeJSON(w, http.StatusOK, Permission{
					Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			perm, err := client.GetPermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, perm)
		})
	}
}

func TestUpdatePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdatePermissionOpts
		expected Permission
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request updates permission via PATCH",
			client:   &Client{APIKey: "test"},
			options:  UpdatePermissionOpts{Slug: "read", Name: stringPtr("Read Access")},
			expected: Permission{
				Object: "permission", Id: "perm_01ABC", Slug: "read", Name: "Read Access",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPatch, r.Method)

				bodyBytes, _ := io.ReadAll(r.Body)
				var rawBody map[string]json.RawMessage
				json.Unmarshal(bodyBytes, &rawBody)

				perm := Permission{
					Object: "permission", Id: "perm_01ABC", Slug: "read",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
				}
				if nameRaw, ok := rawBody["name"]; ok {
					var name string
					json.Unmarshal(nameRaw, &name)
					perm.Name = name
				}

				writeJSON(w, http.StatusOK, perm)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			perm, err := client.UpdatePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, perm)
		})
	}
}

func TestDeletePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeletePermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request deletes permission",
			client:   &Client{APIKey: "test"},
			options:  DeletePermissionOpts{Slug: "read"},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodDelete, r.Method)
				require.True(t, strings.HasSuffix(r.URL.Path, "/read"))

				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeletePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

func TestGetResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetAuthorizationResourceOpts
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns resource by Id",
			client:   &Client{APIKey: "test"},
			options:  GetAuthorizationResourceOpts{ResourceId: "res_01ABC"},
			expected: AuthorizationResource{
				Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
				Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.True(t, strings.HasSuffix(r.URL.Path, "/res_01ABC"))

				writeJSON(w, http.StatusOK, AuthorizationResource{
					Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
					Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			res, err := client.GetResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestCreateResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateAuthorizationResourceOpts
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request creates resource",
			client:   &Client{APIKey: "test"},
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "doc-1",
				Name:             "Document 1",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_01ABC",
			},
			expected: AuthorizationResource{
				Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
				Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request creates resource with parent by Id",
			client:   &Client{APIKey: "test"},
			options: CreateAuthorizationResourceOpts{
				ExternalId:       "page-1",
				Name:             "Page 1",
				ResourceTypeSlug: "page",
				OrganizationId:   "org_01ABC",
				Parent:           ParentResourceIdentifierById{ParentResourceId: "res_parent"},
			},
			expected: AuthorizationResource{
				Object: "authorization_resource", Id: "res_02DEF", ExternalId: "page-1",
				Name: "Page 1", ResourceTypeSlug: "page", OrganizationId: "org_01ABC",
				ParentResourceId: "res_parent",
				CreatedAt:        "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPost, r.Method)

				bodyBytes, _ := io.ReadAll(r.Body)
				var bodyMap map[string]interface{}
				json.Unmarshal(bodyBytes, &bodyMap)

				res := AuthorizationResource{
					Object:           "authorization_resource",
					ExternalId:       bodyMap["external_id"].(string),
					Name:             bodyMap["name"].(string),
					ResourceTypeSlug: bodyMap["resource_type_slug"].(string),
					OrganizationId:   bodyMap["organization_id"].(string),
					CreatedAt:        "2024-01-01T00:00:00Z",
					UpdatedAt:        "2024-01-01T00:00:00Z",
				}

				if parentId, ok := bodyMap["parent_resource_id"]; ok {
					res.Id = "res_02DEF"
					res.ParentResourceId = parentId.(string)
				} else {
					res.Id = "res_01ABC"
				}

				writeJSON(w, http.StatusOK, res)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			res, err := client.CreateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestUpdateResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdateAuthorizationResourceOpts
		expected AuthorizationResource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request updates resource via PATCH",
			client:   &Client{APIKey: "test"},
			options: UpdateAuthorizationResourceOpts{
				ResourceId: "res_01ABC",
				Name:       stringPtr("Updated Document"),
			},
			expected: AuthorizationResource{
				Object: "authorization_resource", Id: "res_01ABC",
				Name: "Updated Document", ResourceTypeSlug: "document",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPatch, r.Method)

				bodyBytes, _ := io.ReadAll(r.Body)
				var rawBody map[string]json.RawMessage
				json.Unmarshal(bodyBytes, &rawBody)

				res := AuthorizationResource{
					Object: "authorization_resource", Id: "res_01ABC",
					ResourceTypeSlug: "document",
					CreatedAt:        "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
				}
				if nameRaw, ok := rawBody["name"]; ok {
					var name string
					json.Unmarshal(nameRaw, &name)
					res.Name = name
				}

				writeJSON(w, http.StatusOK, res)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			res, err := client.UpdateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

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
			err:      true,
		},
		{
			scenario: "Request deletes resource",
			client:   &Client{APIKey: "test"},
			options:  DeleteAuthorizationResourceOpts{ResourceId: "res_01ABC"},
		},
		{
			scenario: "Request deletes resource with cascade",
			client:   &Client{APIKey: "test"},
			options:  DeleteAuthorizationResourceOpts{ResourceId: "res_01ABC", CascadeDelete: true},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodDelete, r.Method)

				if test.options.CascadeDelete {
					require.Equal(t, "true", r.URL.Query().Get("cascade_delete"))
				}

				w.WriteHeader(http.StatusNoContent)
			}))
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
			err:      true,
		},
		{
			scenario: "Request returns list of resources",
			client:   &Client{APIKey: "test"},
			options:  ListAuthorizationResourcesOpts{OrganizationId: "org_01ABC", ResourceTypeSlug: "document"},
			expected: ListAuthorizationResourcesResponse{
				Data: []AuthorizationResource{
					{
						Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
						Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{Before: "", After: ""},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)

				writeJSON(w, http.StatusOK, ListAuthorizationResourcesResponse{
					Data: []AuthorizationResource{
						{
							Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
							Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
							CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
						},
					},
					ListMetadata: common.ListMetadata{Before: "", After: ""},
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			res, err := client.ListResources(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

// ---------------------------------------------------------------------------
// Resources by External Id
// ---------------------------------------------------------------------------

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
			scenario: "Request returns resource by external Id",
			client:   &Client{APIKey: "test"},
			options: GetResourceByExternalIdOpts{
				OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
			},
			expected: AuthorizationResource{
				Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
				Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/resources/document/doc-1", r.URL.Path)

				writeJSON(w, http.StatusOK, AuthorizationResource{
					Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
					Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			res, err := client.GetResourceByExternalId(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
}

func TestUpdateResourceByExternalId(t *testing.T) {
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
			scenario: "Request updates resource by external Id via PATCH",
			client:   &Client{APIKey: "test"},
			options: UpdateResourceByExternalIdOpts{
				OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
				Name: stringPtr("Updated Document"),
			},
			expected: AuthorizationResource{
				Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
				Name: "Updated Document", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPatch, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/resources/document/doc-1", r.URL.Path)

				writeJSON(w, http.StatusOK, AuthorizationResource{
					Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
					Name: "Updated Document", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
					CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z",
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			res, err := client.UpdateResourceByExternalId(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, res)
		})
	}
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
			scenario: "Request deletes resource by external Id",
			client:   &Client{APIKey: "test"},
			options: DeleteResourceByExternalIdOpts{
				OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
			},
		},
		{
			scenario: "Request deletes resource by external Id with cascade",
			client:   &Client{APIKey: "test"},
			options: DeleteResourceByExternalIdOpts{
				OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
				CascadeDelete: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodDelete, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/resources/document/doc-1", r.URL.Path)

				if test.options.CascadeDelete {
					require.Equal(t, "true", r.URL.Query().Get("cascade_delete"))
				}

				w.WriteHeader(http.StatusNoContent)
			}))
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

// ---------------------------------------------------------------------------
// Authorization Check
// ---------------------------------------------------------------------------

func TestCheck(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  AuthorizationCheckOpts
		expected AuthorizationCheckResult
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request checks authorization with resource by Id",
			client:   &Client{APIKey: "test"},
			options: AuthorizationCheckOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read",
				Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
			},
			expected: AuthorizationCheckResult{Authorized: true},
		},
		{
			scenario: "Request checks authorization with resource by external Id",
			client:   &Client{APIKey: "test"},
			options: AuthorizationCheckOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "write",
				Resource: ResourceIdentifierByExternalId{
					ResourceExternalId: "doc-1",
					ResourceTypeSlug:   "document",
				},
			},
			expected: AuthorizationCheckResult{Authorized: false},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/authorization/organization_memberships/om_01ABC/check", r.URL.Path)

				bodyBytes, _ := io.ReadAll(r.Body)
				var bodyMap map[string]interface{}
				require.NoError(t, json.Unmarshal(bodyBytes, &bodyMap))

				permSlug, ok := bodyMap["permission_slug"].(string)
				require.True(t, ok, "request body must contain permission_slug")
				require.NotEmpty(t, permSlug)

				// At least one resource identifier must be present.
				_, hasResId := bodyMap["resource_id"]
				_, hasResExtId := bodyMap["resource_external_id"]
				require.True(t, hasResId || hasResExtId, "request body must contain a resource identifier")

				// Return authorized only for "read" permission.
				authorized := permSlug == "read"

				writeJSON(w, http.StatusOK, AuthorizationCheckResult{Authorized: authorized})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			result, err := client.Check(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Role Assignments
// ---------------------------------------------------------------------------

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
			scenario: "Request returns list of role assignments",
			client:   &Client{APIKey: "test"},
			options:  ListRoleAssignmentsOpts{OrganizationMembershipId: "om_01ABC"},
			expected: ListRoleAssignmentsResponse{
				Data: []RoleAssignment{
					{
						Object: "role_assignment", Id: "ra_01ABC",
						Role:     RoleAssignmentRole{Slug: "admin"},
						Resource: RoleAssignmentResource{Id: "res_01ABC", ResourceTypeSlug: "document"},
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{Before: "", After: ""},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", r.URL.Path)

				writeJSON(w, http.StatusOK, ListRoleAssignmentsResponse{
					Data: []RoleAssignment{
						{
							Object: "role_assignment", Id: "ra_01ABC",
							Role:     RoleAssignmentRole{Slug: "admin"},
							Resource: RoleAssignmentResource{Id: "res_01ABC", ResourceTypeSlug: "document"},
							CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
						},
					},
					ListMetadata: common.ListMetadata{Before: "", After: ""},
				})
			}))
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
			scenario: "Request assigns role with resource by Id",
			client:   &Client{APIKey: "test"},
			options: AssignRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "admin",
				Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
			},
			expected: RoleAssignment{
				Object: "role_assignment", Id: "ra_01ABC",
				Role:     RoleAssignmentRole{Slug: "admin"},
				Resource: RoleAssignmentResource{Id: "res_01ABC", ResourceTypeSlug: "document"},
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request assigns role with resource by external Id",
			client:   &Client{APIKey: "test"},
			options: AssignRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "editor",
				Resource: ResourceIdentifierByExternalId{
					ResourceExternalId: "doc-1",
					ResourceTypeSlug:   "document",
				},
			},
			expected: RoleAssignment{
				Object: "role_assignment", Id: "ra_02DEF",
				Role:     RoleAssignmentRole{Slug: "editor"},
				Resource: RoleAssignmentResource{ExternalId: "doc-1", ResourceTypeSlug: "document"},
				CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", r.URL.Path)

				bodyBytes, _ := io.ReadAll(r.Body)
				var bodyMap map[string]interface{}
				require.NoError(t, json.Unmarshal(bodyBytes, &bodyMap))

				roleSlug, ok := bodyMap["role_slug"].(string)
				require.True(t, ok, "request body must contain role_slug")
				require.NotEmpty(t, roleSlug)

				// Differentiate response based on whether resource_id or resource_external_id is present.
				if resId, ok := bodyMap["resource_id"]; ok {
					require.NotEmpty(t, resId, "resource_id must not be empty when present")
					writeJSON(w, http.StatusOK, RoleAssignment{
						Object: "role_assignment", Id: "ra_01ABC",
						Role:     RoleAssignmentRole{Slug: roleSlug},
						Resource: RoleAssignmentResource{Id: resId.(string), ResourceTypeSlug: "document"},
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					})
				} else {
					extId, ok := bodyMap["resource_external_id"].(string)
					require.True(t, ok, "request body must contain resource_external_id")
					typeSlug, ok := bodyMap["resource_type_slug"].(string)
					require.True(t, ok, "request body must contain resource_type_slug")
					writeJSON(w, http.StatusOK, RoleAssignment{
						Object: "role_assignment", Id: "ra_02DEF",
						Role:     RoleAssignmentRole{Slug: roleSlug},
						Resource: RoleAssignmentResource{ExternalId: extId, ResourceTypeSlug: typeSlug},
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					})
				}
			}))
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
			scenario: "Request removes role",
			client:   &Client{APIKey: "test"},
			options: RemoveRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "admin",
				Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodDelete, r.Method)
				require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments", r.URL.Path)

				bodyBytes, _ := io.ReadAll(r.Body)
				var bodyMap map[string]interface{}
				require.NoError(t, json.Unmarshal(bodyBytes, &bodyMap))
				require.Equal(t, "admin", bodyMap["role_slug"])
				require.Equal(t, "res_01ABC", bodyMap["resource_id"])

				w.WriteHeader(http.StatusNoContent)
			}))
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
			scenario: "Request removes role assignment by Id",
			client:   &Client{APIKey: "test"},
			options: RemoveRoleAssignmentOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleAssignmentId:         "ra_01ABC",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodDelete, r.Method)
				require.Equal(t, "/authorization/organization_memberships/om_01ABC/role_assignments/ra_01ABC", r.URL.Path)

				w.WriteHeader(http.StatusNoContent)
			}))
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

// ---------------------------------------------------------------------------
// Membership / Resource queries
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
			scenario: "Request returns resources for membership",
			client:   &Client{APIKey: "test"},
			options: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read",
			},
			expected: ListAuthorizationResourcesResponse{
				Data: []AuthorizationResource{
					{
						Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
						Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{Before: "", After: ""},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/authorization/organization_memberships/om_01ABC/resources", r.URL.Path)

				writeJSON(w, http.StatusOK, ListAuthorizationResourcesResponse{
					Data: []AuthorizationResource{
						{
							Object: "authorization_resource", Id: "res_01ABC", ExternalId: "doc-1",
							Name: "Document 1", ResourceTypeSlug: "document", OrganizationId: "org_01ABC",
							CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
						},
					},
					ListMetadata: common.ListMetadata{Before: "", After: ""},
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			result, err := client.ListResourcesForMembership(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
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
			scenario: "Request returns memberships for resource",
			client:   &Client{APIKey: "test"},
			options: ListMembershipsForResourceOpts{
				ResourceId:     "res_01ABC",
				PermissionSlug: "read",
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object: "organization_membership", Id: "om_01ABC",
						UserId: "user_01ABC", OrganizationId: "org_01ABC", Status: "active",
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{Before: "", After: ""},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/authorization/resources/res_01ABC/organization_memberships", r.URL.Path)

				writeJSON(w, http.StatusOK, ListAuthorizationOrganizationMembershipsResponse{
					Data: []AuthorizationOrganizationMembership{
						{
							Object: "organization_membership", Id: "om_01ABC",
							UserId: "user_01ABC", OrganizationId: "org_01ABC", Status: "active",
							CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
						},
					},
					ListMetadata: common.ListMetadata{Before: "", After: ""},
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			result, err := client.ListMembershipsForResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
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
			scenario: "Request returns memberships by resource external Id",
			client:   &Client{APIKey: "test"},
			options: ListMembershipsForResourceByExternalIdOpts{
				OrganizationId: "org_01ABC", ResourceTypeSlug: "document", ExternalId: "doc-1",
				PermissionSlug: "read",
			},
			expected: ListAuthorizationOrganizationMembershipsResponse{
				Data: []AuthorizationOrganizationMembership{
					{
						Object: "organization_membership", Id: "om_01ABC",
						UserId: "user_01ABC", OrganizationId: "org_01ABC", Status: "active",
						CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
					},
				},
				ListMetadata: common.ListMetadata{Before: "", After: ""},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authGuard(w, r) {
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/authorization/organizations/org_01ABC/resources/document/doc-1/organization_memberships", r.URL.Path)

				writeJSON(w, http.StatusOK, ListAuthorizationOrganizationMembershipsResponse{
					Data: []AuthorizationOrganizationMembership{
						{
							Object: "organization_membership", Id: "om_01ABC",
							UserId: "user_01ABC", OrganizationId: "org_01ABC", Status: "active",
							CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z",
						},
					},
					ListMetadata: common.ListMetadata{Before: "", After: ""},
				})
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			result, err := client.ListMembershipsForResourceByExternalId(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
}
