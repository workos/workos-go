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

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-viewer",
		Name:           "Viewer",
	})
	require.NoError(t, err)
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

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "org-admin",
		Description:    nil,
	})
	require.NoError(t, err)
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

func stringPtr(s string) *string {
	return &s
}
