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

// Helper to create a *string pointer for update opts.
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

// ---------------------------------------------------------------------------
// CreateOrganizationRole
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
			scenario: "Request creates org role and returns OrganizationRole",
			client: &Client{
				APIKey: "test",
			},
			options: CreateOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "org-admin",
				Name:           "Org Admin",
			},
			expected: OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Org Admin",
				Slug:        "org-admin",
				Description: "",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
		},
		{
			scenario: "Request with description includes it in the response",
			client: &Client{
				APIKey: "test",
			},
			options: CreateOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "org-editor",
				Name:           "Org Editor",
				Description:    "Can edit things",
			},
			expected: OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Org Editor",
				Slug:        "org-editor",
				Description: "Can edit things",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createOrganizationRoleTestHandler))
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

func createOrganizationRoleTestHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organizations/org_01ABC/roles") {
		http.Error(w, "bad path", http.StatusNotFound)
		return
	}

	var opts CreateOrganizationRoleOpts
	json.NewDecoder(r.Body).Decode(&opts)

	if opts.Slug == "" || opts.Name == "" {
		http.Error(w, "slug and name are required", http.StatusBadRequest)
		return
	}

	role := OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        opts.Name,
		Slug:        opts.Slug,
		Description: opts.Description,
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	}

	body, err := json.Marshal(role)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateOrganizationRoleOmitsOptionalFields(t *testing.T) {
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

	client := newTestClient(server, "test")

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-viewer",
		Name:           "Viewer",
	})
	require.NoError(t, err)
}

func TestCreateOrganizationRoleUsesPostMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"Admin","slug":"admin","description":"","permissions":[],"resource_type_slug":"","type":"OrganizationRole","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		Name:           "Admin",
	})
	require.NoError(t, err)
}

func TestCreateOrganizationRoleSendsCorrectPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"Admin","slug":"admin","description":"","permissions":[],"resource_type_slug":"","type":"OrganizationRole","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01XYZ",
		Slug:           "admin",
		Name:           "Admin",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ListOrganizationRoles
// ---------------------------------------------------------------------------

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
			scenario: "Request returns list of roles for the organization",
			client: &Client{
				APIKey: "test",
			},
			options: ListOrganizationRolesOpts{
				OrganizationId: "org_01ABC",
			},
			expected: ListOrganizationRolesResponse{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listOrganizationRolesTestHandler))
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

func listOrganizationRolesTestHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organizations/org_01ABC/roles") {
		http.Error(w, "bad path", http.StatusNotFound)
		return
	}

	body, err := json.Marshal(ListOrganizationRolesResponse{
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
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListOrganizationRolesUsesGetMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})
	require.NoError(t, err)
}

func TestListOrganizationRolesReturnsEmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	resp, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})
	require.NoError(t, err)
	require.Empty(t, resp.Data)
}

// ---------------------------------------------------------------------------
// GetOrganizationRole
// ---------------------------------------------------------------------------

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
			scenario: "Request returns OrganizationRole by org ID and slug",
			client: &Client{
				APIKey: "test",
			},
			options: GetOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "org-admin",
			},
			expected: OrganizationRole{
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

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getOrganizationRoleTestHandler))
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

func getOrganizationRoleTestHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organizations/org_01ABC/roles/org-admin") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	body, err := json.Marshal(OrganizationRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "org-admin",
		Permissions: []string{"read", "write"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestGetOrganizationRoleSendsCorrectPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles/my-role", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"My Role","slug":"my-role","description":"","permissions":[],"resource_type_slug":"","type":"OrganizationRole","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01XYZ",
		Slug:           "my-role",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// UpdateOrganizationRole
// ---------------------------------------------------------------------------

func TestUpdateOrganizationRole(t *testing.T) {
	updatedName := "Super Admin"

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
			scenario: "Request uses PATCH method and updates name",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "org-admin",
				Name:           &updatedName,
			},
			expected: OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Super Admin",
				Slug:        "org-admin",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Request sets description to null",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "org-admin",
				Description:    nil,
			},
			expected: OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Slug:        "org-admin",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Request updates description only",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "org-admin",
				Description:    stringPtr("New description"),
			},
			expected: OrganizationRole{
				Object:      "role",
				Id:          "role_01ABC",
				Slug:        "org-admin",
				Description: "New description",
				Permissions: []string{"read", "write"},
				Type:        "OrganizationRole",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateOrganizationRoleTestHandler))
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

func updateOrganizationRoleTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
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
			role.Description = ""
		} else {
			var desc string
			json.Unmarshal(descRaw, &desc)
			role.Description = desc
		}
	}

	body, err := json.Marshal(role)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// TestUpdateOrganizationRoleNullDescriptionBody verifies that a nil *string
// Description always serializes as "description":null in the JSON body.
// Go's encoding/json cannot distinguish between "field was not provided" and
// "field was explicitly set to null" when using a pointer type without
// omitempty. This is an accepted trade-off of the current struct design:
// every PATCH request will include "description":null when the caller does
// not set Description, which the API treats as a no-op clear.
func TestUpdateOrganizationRoleNullDescriptionBody(t *testing.T) {
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

	client := newTestClient(server, "test")

	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
		Description:    nil,
	})
	require.NoError(t, err)
}

func TestUpdateOrganizationRoleSendsCorrectPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles/editor", r.URL.Path)
		require.Equal(t, http.MethodPatch, r.Method)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"Editor","slug":"editor","description":"","permissions":[],"resource_type_slug":"","type":"OrganizationRole","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-02T00:00:00Z"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01XYZ",
		Slug:           "editor",
		Name:           stringPtr("Editor"),
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// DeleteOrganizationRole
// ---------------------------------------------------------------------------

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
			scenario: "Successful delete returns nil error",
			client: &Client{
				APIKey: "test",
			},
			options: DeleteOrganizationRoleOpts{
				OrganizationId: "org_01ABC",
				Slug:           "org-admin",
			},
			err: false,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteOrganizationRoleTestHandler))
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

func deleteOrganizationRoleTestHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organizations/org_01ABC/roles/org-admin") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func TestDeleteOrganizationRoleSendsCorrectPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/authorization/organizations/org_01XYZ/roles/viewer", r.URL.Path)
		require.Equal(t, http.MethodDelete, r.Method)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01XYZ",
		Slug:           "viewer",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Error response tests (4xx / 5xx)
// ---------------------------------------------------------------------------

func TestCreateOrganizationRoleReturnsErrorOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Organization not found"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_nonexistent",
		Slug:           "admin",
		Name:           "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestCreateOrganizationRoleReturnsErrorOn500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		Name:           "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestListOrganizationRolesReturnsErrorOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Organization not found"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_nonexistent",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestListOrganizationRolesReturnsErrorOn500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestGetOrganizationRoleReturnsErrorOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Role not found"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "nonexistent-role",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestGetOrganizationRoleReturnsErrorOn500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestUpdateOrganizationRoleReturnsErrorOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Role not found"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "nonexistent-role",
		Name:           stringPtr("Updated"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestUpdateOrganizationRoleReturnsErrorOn500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
		Name:           stringPtr("Updated"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestDeleteOrganizationRoleReturnsErrorOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Role not found"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "nonexistent-role",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestDeleteOrganizationRoleReturnsErrorOn500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestCreateOrganizationRoleReturnsErrorOnInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		Name:           "Admin",
	})
	require.Error(t, err)
}

func TestGetOrganizationRoleReturnsErrorOnInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	client := newTestClient(server, "test")

	_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Stub method tests -- verify that unimplemented methods return expected error
// ---------------------------------------------------------------------------

func TestCreateEnvironmentRoleNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug: "admin",
		Name: "Admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListEnvironmentRolesNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetEnvironmentRoleNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateEnvironmentRoleNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{Slug: "admin"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestSetEnvironmentRolePermissionsNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddEnvironmentRolePermissionNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestSetOrganizationRolePermissionsNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		Permissions:    []string{"read"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddOrganizationRolePermissionNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveOrganizationRolePermissionNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := client.RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "admin",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreatePermissionNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "read",
		Name: "Read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListPermissionsNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetPermissionNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.GetPermission(context.Background(), GetPermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdatePermissionNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeletePermissionNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := client.DeletePermission(context.Background(), DeletePermissionOpts{Slug: "read"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetResourceNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreateResourceNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_01",
		Name:             "Test",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateResourceNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResourceNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{ResourceId: "res_01ABC"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListResourcesNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetResourceByExternalIdNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateResourceByExternalIdNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResourceByExternalIdNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCheckNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "read",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListRoleAssignmentsNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAssignRoleNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveRoleNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := client.RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01ABC"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveRoleAssignmentNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleAssignmentId:         "ra_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListResourcesForMembershipNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResourceNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "res_01ABC",
		PermissionSlug: "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResourceByExternalIdNotImplemented(t *testing.T) {
	client := &Client{APIKey: "test", Endpoint: "https://api.workos.com"}
	_, err := client.ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_01",
		PermissionSlug:   "read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
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
