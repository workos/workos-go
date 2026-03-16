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

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool { return &b }

// newTestClient returns a Client wired to the given test server.
func newTestClient(server *httptest.Server, apiKey string) *Client {
	return &Client{
		APIKey:     apiKey,
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

// unauthorizedHandler rejects requests missing a valid Bearer token.
func unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
}

// ---------------------------------------------------------------------------
// Environment Role Tests
// ---------------------------------------------------------------------------

func TestCreateEnvironmentRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     CreateEnvironmentRoleOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     CreateEnvironmentRoleOpts{Slug: "admin", Name: "Admin"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     CreateEnvironmentRoleOpts{Slug: "admin", Name: "Admin"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.CreateEnvironmentRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestListEnvironmentRoles(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListEnvironmentRoles(context.Background())
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetEnvironmentRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     GetEnvironmentRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     GetEnvironmentRoleOpts{RoleSlug: "admin"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     GetEnvironmentRoleOpts{RoleSlug: "admin"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.GetEnvironmentRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUpdateEnvironmentRole(t *testing.T) {
	name := "Updated Admin"
	tests := []struct {
		scenario string
		client   *Client
		opts     UpdateEnvironmentRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     UpdateEnvironmentRoleOpts{RoleSlug: "admin", Name: &name},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     UpdateEnvironmentRoleOpts{RoleSlug: "admin", Name: &name},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.UpdateEnvironmentRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Organization Role Tests
// ---------------------------------------------------------------------------

func TestCreateOrganizationRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     CreateOrganizationRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     CreateOrganizationRoleOpts{OrganizationId: "org_123", Slug: "admin", Name: "Admin"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     CreateOrganizationRoleOpts{OrganizationId: "org_123", Slug: "admin", Name: "Admin"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.CreateOrganizationRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestListOrganizationRoles(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     ListOrganizationRolesOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     ListOrganizationRolesOpts{OrganizationId: "org_123"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     ListOrganizationRolesOpts{OrganizationId: "org_123"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListOrganizationRoles(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetOrganizationRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     GetOrganizationRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     GetOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     GetOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.GetOrganizationRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUpdateOrganizationRole(t *testing.T) {
	name := "Updated Org Admin"
	tests := []struct {
		scenario string
		client   *Client
		opts     UpdateOrganizationRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     UpdateOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin", Name: &name},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     UpdateOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin", Name: &name},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.UpdateOrganizationRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeleteOrganizationRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     DeleteOrganizationRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     DeleteOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     DeleteOrganizationRoleOpts{OrganizationId: "org_123", RoleSlug: "admin"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeleteOrganizationRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Environment Role Permission Tests (implemented methods)
// ---------------------------------------------------------------------------

func TestSetEnvironmentRolePermissions(t *testing.T) {
	expectedRole := EnvironmentRole{
		Object:           "role",
		Id:               "role_01ABC",
		Name:             "Admin",
		Slug:             "admin",
		Description:      "Administrator role",
		Permissions:      []string{"read:users", "write:users"},
		ResourceTypeSlug: "",
		Type:             "EnvironmentRole",
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-02T00:00:00Z",
	}

	tests := []struct {
		scenario string
		client   *Client
		opts     SetEnvironmentRolePermissionsOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: SetEnvironmentRolePermissionsOpts{
				RoleSlug:        "admin",
				Permissions: []string{"read:users"},
			},
			err: true,
		},
		{
			scenario: "Successful request returns environment role",
			client:   &Client{APIKey: "test"},
			opts: SetEnvironmentRolePermissionsOpts{
				RoleSlug:        "admin",
				Permissions: []string{"read:users", "write:users"},
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(setEnvironmentRolePermissionsHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.SetEnvironmentRolePermissions(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func setEnvironmentRolePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.HasSuffix(r.URL.Path, "/authorization/roles/admin/permissions") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	bodyBytes, _ := io.ReadAll(r.Body)
	var reqBody map[string][]string
	json.Unmarshal(bodyBytes, &reqBody)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(EnvironmentRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "admin",
		Description: "Administrator role",
		Permissions: reqBody["permissions"],
		Type:        "EnvironmentRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	})
}

func TestSetEnvironmentRolePermissions_VerifiesRequestURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Equal(t, "/authorization/roles/editor/permissions", r.URL.Path)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnvironmentRole{Slug: "editor"})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		RoleSlug:        "editor",
		Permissions: []string{"read:docs"},
	})
	require.NoError(t, err)
}

func TestSetEnvironmentRolePermissions_BodyExcludesSlug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		require.False(t, strings.Contains(string(bodyBytes), `"slug"`),
			"slug should not appear in request body")
		require.True(t, strings.Contains(string(bodyBytes), `"permissions"`),
			"permissions should appear in request body")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnvironmentRole{Slug: "admin"})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		RoleSlug:        "admin",
		Permissions: []string{"read:users"},
	})
	require.NoError(t, err)
}

func TestSetEnvironmentRolePermissions_EmptyPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		var reqBody map[string]interface{}
		json.Unmarshal(bodyBytes, &reqBody)

		// Sending empty permissions should still work as a valid request
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnvironmentRole{
			Slug:        "admin",
			Permissions: []string{},
		})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	role, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		RoleSlug:        "admin",
		Permissions: []string{},
	})
	require.NoError(t, err)
	require.Empty(t, role.Permissions)
}

func TestAddEnvironmentRolePermission(t *testing.T) {
	expectedRole := EnvironmentRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "admin",
		Description: "Administrator role",
		Permissions: []string{"read:users", "write:users", "delete:users"},
		Type:        "EnvironmentRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	}

	tests := []struct {
		scenario string
		client   *Client
		opts     AddEnvironmentRolePermissionOpts
		expected EnvironmentRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: AddEnvironmentRolePermissionOpts{
				RoleSlug:           "admin",
				PermissionSlug: "delete:users",
			},
			err: true,
		},
		{
			scenario: "Successful request returns environment role",
			client:   &Client{APIKey: "test"},
			opts: AddEnvironmentRolePermissionOpts{
				RoleSlug:           "admin",
				PermissionSlug: "delete:users",
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(addEnvironmentRolePermissionHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.AddEnvironmentRolePermission(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func addEnvironmentRolePermissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/roles/admin/permissions") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(EnvironmentRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "admin",
		Description: "Administrator role",
		Permissions: []string{"read:users", "write:users", "delete:users"},
		Type:        "EnvironmentRole",
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	})
}

func TestAddEnvironmentRolePermission_VerifiesRequestDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/authorization/roles/admin/permissions", r.URL.Path)
		require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")

		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqBody map[string]string
		require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))
		require.Equal(t, "delete:users", reqBody["slug"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnvironmentRole{Slug: "admin"})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		RoleSlug:           "admin",
		PermissionSlug: "delete:users",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Organization Role Permission Tests (implemented methods)
// ---------------------------------------------------------------------------

func TestSetOrganizationRolePermissions(t *testing.T) {
	expectedRole := OrganizationRole{
		Object:      "role",
		Id:          "role_02DEF",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Description: "Organization admin role",
		Permissions: []string{"manage:billing", "manage:members"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-02-01T00:00:00Z",
		UpdatedAt:   "2024-02-02T00:00:00Z",
	}

	tests := []struct {
		scenario string
		client   *Client
		opts     SetOrganizationRolePermissionsOpts
		expected OrganizationRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: SetOrganizationRolePermissionsOpts{
				OrganizationId: "org_123",
				RoleSlug:           "org-admin",
				Permissions:    []string{"manage:billing"},
			},
			err: true,
		},
		{
			scenario: "Successful request returns organization role",
			client:   &Client{APIKey: "test"},
			opts: SetOrganizationRolePermissionsOpts{
				OrganizationId: "org_123",
				RoleSlug:           "org-admin",
				Permissions:    []string{"manage:billing", "manage:members"},
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(setOrganizationRolePermissionsHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.SetOrganizationRolePermissions(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func setOrganizationRolePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organizations/org_123/roles/org-admin/permissions") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	bodyBytes, _ := io.ReadAll(r.Body)
	var reqBody map[string][]string
	json.Unmarshal(bodyBytes, &reqBody)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(OrganizationRole{
		Object:      "role",
		Id:          "role_02DEF",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Description: "Organization admin role",
		Permissions: reqBody["permissions"],
		Type:        "OrganizationRole",
		CreatedAt:   "2024-02-01T00:00:00Z",
		UpdatedAt:   "2024-02-02T00:00:00Z",
	})
}

func TestSetOrganizationRolePermissions_VerifiesRequestURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Equal(t, "/authorization/organizations/org_456/roles/viewer/permissions", r.URL.Path)
		require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")

		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqBody map[string][]string
		require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))
		require.Equal(t, []string{"read:docs"}, reqBody["permissions"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(OrganizationRole{Slug: "viewer"})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_456",
		RoleSlug:           "viewer",
		Permissions:    []string{"read:docs"},
	})
	require.NoError(t, err)
}

func TestSetOrganizationRolePermissions_BodyExcludesPathParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var reqBody map[string]interface{}
		require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))

		require.Contains(t, reqBody, "permissions")
		require.NotContains(t, reqBody, "organization_id")
		require.NotContains(t, reqBody, "slug")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(OrganizationRole{Slug: "org-admin"})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_123",
		RoleSlug:           "org-admin",
		Permissions:    []string{"manage:billing"},
	})
	require.NoError(t, err)
}

func TestAddOrganizationRolePermission(t *testing.T) {
	expectedRole := OrganizationRole{
		Object:      "role",
		Id:          "role_02DEF",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Description: "Organization admin role",
		Permissions: []string{"manage:billing", "manage:members", "manage:settings"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-02-01T00:00:00Z",
		UpdatedAt:   "2024-02-02T00:00:00Z",
	}

	tests := []struct {
		scenario string
		client   *Client
		opts     AddOrganizationRolePermissionOpts
		expected OrganizationRole
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: AddOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				RoleSlug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
			err: true,
		},
		{
			scenario: "Successful request returns organization role",
			client:   &Client{APIKey: "test"},
			opts: AddOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				RoleSlug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(addOrganizationRolePermissionHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.AddOrganizationRolePermission(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

func addOrganizationRolePermissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organizations/org_123/roles/org-admin/permissions") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(OrganizationRole{
		Object:      "role",
		Id:          "role_02DEF",
		Name:        "Org Admin",
		Slug:        "org-admin",
		Description: "Organization admin role",
		Permissions: []string{"manage:billing", "manage:members", "manage:settings"},
		Type:        "OrganizationRole",
		CreatedAt:   "2024-02-01T00:00:00Z",
		UpdatedAt:   "2024-02-02T00:00:00Z",
	})
}

func TestAddOrganizationRolePermission_VerifiesRequestDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/authorization/organizations/org_123/roles/org-admin/permissions", r.URL.Path)
		require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")

		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqBody map[string]string
		require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))
		require.Equal(t, "manage:settings", reqBody["slug"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(OrganizationRole{Slug: "org-admin"})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		RoleSlug:           "org-admin",
		PermissionSlug: "manage:settings",
	})
	require.NoError(t, err)
}

func TestAddOrganizationRolePermission_BodyExcludesPathParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var reqBody map[string]interface{}
		require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))

		// Only the permission slug should be in the body
		require.Contains(t, reqBody, "slug")
		require.NotContains(t, reqBody, "organization_id")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(OrganizationRole{Slug: "org-admin"})
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	_, err := client.AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		RoleSlug:           "org-admin",
		PermissionSlug: "manage:settings",
	})
	require.NoError(t, err)
}

func TestRemoveOrganizationRolePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     RemoveOrganizationRolePermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: RemoveOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				RoleSlug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
			err: true,
		},
		{
			scenario: "Successful request returns no error",
			client:   &Client{APIKey: "test"},
			opts: RemoveOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				RoleSlug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(removeOrganizationRolePermissionHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.RemoveOrganizationRolePermission(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func removeOrganizationRolePermissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/organizations/org_123/roles/org-admin/permissions/manage:settings") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func TestRemoveOrganizationRolePermission_VerifiesRequestURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/authorization/organizations/org_123/roles/org-admin/permissions/manage:settings", r.URL.Path)
		require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := newTestClient(server, "test")
	err := client.RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		RoleSlug:           "org-admin",
		PermissionSlug: "manage:settings",
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Permission CRUD Tests (stub methods)
// ---------------------------------------------------------------------------

func TestCreatePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     CreatePermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     CreatePermissionOpts{Slug: "read:users", Name: "Read Users"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     CreatePermissionOpts{Slug: "read:users", Name: "Read Users", Description: "Can read users"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.CreatePermission(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestListPermissions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     ListPermissionsOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     ListPermissionsOpts{},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     ListPermissionsOpts{Limit: 10, Order: common.Asc},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListPermissions(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetPermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     GetPermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     GetPermissionOpts{Slug: "read:users"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     GetPermissionOpts{Slug: "read:users"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.GetPermission(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUpdatePermission(t *testing.T) {
	name := "Updated Read Users"
	tests := []struct {
		scenario string
		client   *Client
		opts     UpdatePermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     UpdatePermissionOpts{Slug: "read:users", Name: &name},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     UpdatePermissionOpts{Slug: "read:users", Name: &name},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.UpdatePermission(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeletePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     DeletePermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     DeletePermissionOpts{Slug: "read:users"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     DeletePermissionOpts{Slug: "read:users"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeletePermission(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Resource CRUD Tests (stub methods)
// ---------------------------------------------------------------------------

func TestGetResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     GetAuthorizationResourceOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     GetAuthorizationResourceOpts{ResourceId: "resource_01ABC"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     GetAuthorizationResourceOpts{ResourceId: "resource_01ABC"},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.GetResource(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCreateResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     CreateAuthorizationResourceOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "My Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: CreateAuthorizationResourceOpts{
				ExternalId:       "ext_123",
				Name:             "My Resource",
				ResourceTypeSlug: "document",
				OrganizationId:   "org_123",
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.CreateResource(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUpdateResource(t *testing.T) {
	name := "Updated Resource"
	tests := []struct {
		scenario string
		client   *Client
		opts     UpdateAuthorizationResourceOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     UpdateAuthorizationResourceOpts{ResourceId: "resource_01ABC", Name: &name},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     UpdateAuthorizationResourceOpts{ResourceId: "resource_01ABC", Name: &name},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.UpdateResource(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeleteResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     DeleteAuthorizationResourceOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     DeleteAuthorizationResourceOpts{ResourceId: "resource_01ABC"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     DeleteAuthorizationResourceOpts{ResourceId: "resource_01ABC"},
			err:      true,
		},
		{
			scenario: "Stub with cascade delete returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts:     DeleteAuthorizationResourceOpts{ResourceId: "resource_01ABC", CascadeDelete: boolPtr(true)},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeleteResource(context.Background(), test.opts)
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
		opts     ListAuthorizationResourcesOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     ListAuthorizationResourcesOpts{OrganizationId: "org_123"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListAuthorizationResourcesOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				Limit:            10,
				Order:            common.Desc,
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListResources(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Resource By External ID Tests (stub methods)
// ---------------------------------------------------------------------------

func TestGetResourceByExternalId(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     GetResourceByExternalIdOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: GetResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: GetResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.GetResourceByExternalId(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUpdateResourceByExternalId(t *testing.T) {
	name := "Updated Document"
	tests := []struct {
		scenario string
		client   *Client
		opts     UpdateResourceByExternalIdOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: UpdateResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
				Name:             &name,
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: UpdateResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
				Name:             &name,
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.UpdateResourceByExternalId(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDeleteResourceByExternalId(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     DeleteResourceByExternalIdOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: DeleteResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: DeleteResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
			},
			err: true,
		},
		{
			scenario: "Stub with cascade delete returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: DeleteResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
				CascadeDelete:    boolPtr(true),
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.DeleteResourceByExternalId(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Authorization Check Tests (stub methods)
// ---------------------------------------------------------------------------

func TestCheck(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     AuthorizationCheckOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: AuthorizationCheckOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read:docs",
				ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error with ResourceIdentifierById",
			client:   &Client{APIKey: "test"},
			opts: AuthorizationCheckOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read:docs",
				ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error with ResourceIdentifierByExternalId",
			client:   &Client{APIKey: "test"},
			opts: AuthorizationCheckOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read:docs",
				ResourceIdentifier: ResourceIdentifierByExternalId{
					ResourceExternalId: "ext_123",
					ResourceTypeSlug:   "document",
				},
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.Check(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Role Assignment Tests (stub methods)
// ---------------------------------------------------------------------------

func TestListRoleAssignments(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     ListRoleAssignmentsOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts:     ListRoleAssignmentsOpts{OrganizationMembershipId: "om_01ABC"},
			err:      true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListRoleAssignmentsOpts{
				OrganizationMembershipId: "om_01ABC",
				Limit:                    20,
				Order:                    common.Desc,
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListRoleAssignments(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAssignRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     AssignRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: AssignRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "admin",
				ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error with ResourceIdentifierById",
			client:   &Client{APIKey: "test"},
			opts: AssignRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "admin",
				ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error with ResourceIdentifierByExternalId",
			client:   &Client{APIKey: "test"},
			opts: AssignRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "admin",
				ResourceIdentifier: ResourceIdentifierByExternalId{
					ResourceExternalId: "ext_123",
					ResourceTypeSlug:   "document",
				},
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.AssignRole(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRemoveRole(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     RemoveRoleOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: RemoveRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "admin",
				ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: RemoveRoleOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleSlug:                 "admin",
				ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.RemoveRole(context.Background(), test.opts)
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
		opts     RemoveRoleAssignmentOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: RemoveRoleAssignmentOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleAssignmentId:         "ra_01XYZ",
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: RemoveRoleAssignmentOpts{
				OrganizationMembershipId: "om_01ABC",
				RoleAssignmentId:         "ra_01XYZ",
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.RemoveRoleAssignment(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Membership / Resource Query Tests (stub methods)
// ---------------------------------------------------------------------------

func TestListResourcesForMembership(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     ListResourcesForMembershipOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read:docs",
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read:docs",
				Limit:                    10,
			},
			err: true,
		},
		{
			scenario: "Stub with parent resource by Id returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read:docs",
				ParentResourceId:         "parent_01ABC",
			},
			err: true,
		},
		{
			scenario: "Stub with parent resource by external Id returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListResourcesForMembershipOpts{
				OrganizationMembershipId: "om_01ABC",
				PermissionSlug:           "read:docs",
				ParentResourceExternalId: "ext_parent",
				ParentResourceTypeSlug:   "folder",
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListResourcesForMembership(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestListMembershipsForResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     ListMembershipsForResourceOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: ListMembershipsForResourceOpts{
				ResourceId:     "resource_01ABC",
				PermissionSlug: "read:docs",
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListMembershipsForResourceOpts{
				ResourceId:     "resource_01ABC",
				PermissionSlug: "read:docs",
				Limit:          10,
			},
			err: true,
		},
		{
			scenario: "Stub with assignment filter returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListMembershipsForResourceOpts{
				ResourceId:     "resource_01ABC",
				PermissionSlug: "read:docs",
				Assignment:     AssignmentDirect,
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListMembershipsForResource(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestListMembershipsForResourceByExternalId(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		opts     ListMembershipsForResourceByExternalIdOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: ListMembershipsForResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
				PermissionSlug:   "read:docs",
			},
			err: true,
		},
		{
			scenario: "Stub returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListMembershipsForResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
				PermissionSlug:   "read:docs",
				Limit:            10,
			},
			err: true,
		},
		{
			scenario: "Stub with assignment filter returns not implemented error",
			client:   &Client{APIKey: "test"},
			opts: ListMembershipsForResourceByExternalIdOpts{
				OrganizationId:   "org_123",
				ResourceTypeSlug: "document",
				ExternalId:       "ext_456",
				PermissionSlug:   "read:docs",
				Assignment:       AssignmentType("inherited"),
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(unauthorizedHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			_, err := client.ListMembershipsForResourceByExternalId(context.Background(), test.opts)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// ResourceIdentifier Interface Tests
// ---------------------------------------------------------------------------

func TestResourceIdentifierById_Params(t *testing.T) {
	r := ResourceIdentifierById{ResourceId: "resource_01ABC"}
	params := r.resourceIdentifierParams()
	require.Equal(t, "resource_01ABC", params["resource_id"])
	require.Len(t, params, 1)
}

func TestResourceIdentifierByExternalId_Params(t *testing.T) {
	r := ResourceIdentifierByExternalId{
		ResourceExternalId: "ext_123",
		ResourceTypeSlug:   "document",
	}
	params := r.resourceIdentifierParams()
	require.Equal(t, "ext_123", params["resource_external_id"])
	require.Equal(t, "document", params["resource_type_slug"])
	require.Len(t, params, 2)
}

func TestParentResourceIdentifierById_Params(t *testing.T) {
	r := ParentResourceIdentifierById{ParentResourceId: "parent_01ABC"}
	params := r.parentResourceIdentifierParams()
	require.Equal(t, "parent_01ABC", params["parent_resource_id"])
	require.Len(t, params, 1)
}

func TestParentResourceIdentifierByExternalId_Params(t *testing.T) {
	r := ParentResourceIdentifierByExternalId{
		ParentResourceExternalId: "ext_parent",
		ParentResourceTypeSlug:   "folder",
	}
	params := r.parentResourceIdentifierParams()
	require.Equal(t, "ext_parent", params["parent_resource_external_id"])
	require.Equal(t, "folder", params["parent_resource_type_slug"])
	require.Len(t, params, 2)
}

// ---------------------------------------------------------------------------
// Client Init Tests
// ---------------------------------------------------------------------------

func TestClientInit_DefaultValues(t *testing.T) {
	client := &Client{}
	client.init()

	require.NotNil(t, client.HTTPClient)
	require.Equal(t, "https://api.workos.com", client.Endpoint)
	require.NotNil(t, client.JSONEncode)
}

func TestClientInit_PreservesExistingValues(t *testing.T) {
	customEndpoint := "https://custom.workos.com"
	client := &Client{
		Endpoint: customEndpoint,
	}
	client.init()

	require.Equal(t, customEndpoint, client.Endpoint)
}

func TestClientInit_OnlyRunsOnce(t *testing.T) {
	client := &Client{}
	client.init()

	// Change endpoint after init
	client.Endpoint = "https://changed.workos.com"

	// Second call to init via once.Do should be a no-op
	client.once.Do(client.init)
	require.Equal(t, "https://changed.workos.com", client.Endpoint)
}
