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
		wantErr  bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: SetEnvironmentRolePermissionsOpts{
				Slug:        "admin",
				Permissions: []string{"read:users"},
			},
			wantErr: true,
		},
		{
			scenario: "Successful request returns environment role",
			client: &Client{
				APIKey: "test_api_key",
			},
			opts: SetEnvironmentRolePermissionsOpts{
				Slug:        "admin",
				Permissions: []string{"read:users", "write:users"},
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test_api_key" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

				require.Equal(t, http.MethodPut, r.Method)
				require.Equal(t, "/authorization/roles/admin/permissions", r.URL.Path)
				require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")

				bodyBytes, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				var reqBody map[string][]string
				require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))
				require.Equal(t, []string{"read:users", "write:users"}, reqBody["permissions"])

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(expectedRole)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.SetEnvironmentRolePermissions(context.Background(), test.opts)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
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
		wantErr  bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: AddEnvironmentRolePermissionOpts{
				Slug:           "admin",
				PermissionSlug: "delete:users",
			},
			wantErr: true,
		},
		{
			scenario: "Successful request returns environment role",
			client: &Client{
				APIKey: "test_api_key",
			},
			opts: AddEnvironmentRolePermissionOpts{
				Slug:           "admin",
				PermissionSlug: "delete:users",
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test_api_key" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

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
				json.NewEncoder(w).Encode(expectedRole)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.AddEnvironmentRolePermission(context.Background(), test.opts)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
}

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
		wantErr  bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: SetOrganizationRolePermissionsOpts{
				OrganizationId: "org_123",
				Slug:           "org-admin",
				Permissions:    []string{"manage:billing"},
			},
			wantErr: true,
		},
		{
			scenario: "Successful request returns organization role",
			client: &Client{
				APIKey: "test_api_key",
			},
			opts: SetOrganizationRolePermissionsOpts{
				OrganizationId: "org_123",
				Slug:           "org-admin",
				Permissions:    []string{"manage:billing", "manage:members"},
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test_api_key" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

				require.Equal(t, http.MethodPut, r.Method)
				require.Equal(t, "/authorization/organizations/org_123/roles/org-admin/permissions", r.URL.Path)
				require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")

				bodyBytes, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				var reqBody map[string][]string
				require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))
				require.Equal(t, []string{"manage:billing", "manage:members"}, reqBody["permissions"])

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(expectedRole)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.SetOrganizationRolePermissions(context.Background(), test.opts)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, role)
		})
	}
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
		wantErr  bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: AddOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				Slug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
			wantErr: true,
		},
		{
			scenario: "Successful request returns organization role",
			client: &Client{
				APIKey: "test_api_key",
			},
			opts: AddOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				Slug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
			expected: expectedRole,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test_api_key" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

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
				json.NewEncoder(w).Encode(expectedRole)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			role, err := client.AddOrganizationRolePermission(context.Background(), test.opts)
			if test.wantErr {
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
		opts     RemoveOrganizationRolePermissionOpts
		wantErr  bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			opts: RemoveOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				Slug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
			wantErr: true,
		},
		{
			scenario: "Successful request returns no error",
			client: &Client{
				APIKey: "test_api_key",
			},
			opts: RemoveOrganizationRolePermissionOpts{
				OrganizationId: "org_123",
				Slug:           "org-admin",
				PermissionSlug: "manage:settings",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer test_api_key" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

				require.Equal(t, http.MethodDelete, r.Method)
				require.Equal(t, "/authorization/organizations/org_123/roles/org-admin/permissions/manage:settings", r.URL.Path)
				require.Contains(t, r.Header.Get("User-Agent"), "workos-go/")

				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			err := client.RemoveOrganizationRolePermission(context.Background(), test.opts)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSetEnvironmentRolePermissions_BodyExcludesSlug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		// Verify the slug field is NOT in the JSON body (it has json:"-")
		require.False(t, strings.Contains(string(bodyBytes), `"slug"`),
			"slug should not appear in request body")
		require.True(t, strings.Contains(string(bodyBytes), `"permissions"`),
			"permissions should appear in request body")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnvironmentRole{Slug: "admin"})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test_api_key",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"read:users"},
	})
	require.NoError(t, err)
}

func TestAddOrganizationRolePermission_BodyExcludesPathParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var reqBody map[string]interface{}
		require.NoError(t, json.Unmarshal(bodyBytes, &reqBody))

		// Only "slug" (the permission slug) should be in the body
		require.Contains(t, reqBody, "slug")
		require.NotContains(t, reqBody, "organization_id")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(OrganizationRole{Slug: "org-admin"})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test_api_key",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_123",
		Slug:           "org-admin",
		PermissionSlug: "manage:settings",
	})
	require.NoError(t, err)
}
