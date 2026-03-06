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
			client: &Client{
				APIKey: "test",
			},
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
			client: &Client{
				APIKey: "test",
			},
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
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var opts CreateEnvironmentRoleOpts
	json.NewDecoder(r.Body).Decode(&opts)

	if opts.Slug == "" || opts.Name == "" {
		http.Error(w, "slug and name are required", http.StatusBadRequest)
		return
	}

	role := EnvironmentRole{
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
	}

	body, err := json.Marshal(role)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
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

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"Viewer","slug":"viewer","description":"","permissions":["read"],"resource_type_slug":"","type":"environment","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

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
			client: &Client{
				APIKey: "test",
			},
			expected: ListEnvironmentRolesResponse{
				Data: []EnvironmentRole{
					{
						Object:      "role",
						Id:          "role_01ABC",
						Name:        "Admin",
						Slug:        "admin",
						Permissions: []string{"read", "write"},
						Type:        "environment",
						CreatedAt:   "2024-01-01T00:00:00Z",
						UpdatedAt:   "2024-01-01T00:00:00Z",
					},
					{
						Object:      "role",
						Id:          "role_02DEF",
						Name:        "Viewer",
						Slug:        "viewer",
						Permissions: []string{"read"},
						Type:        "environment",
						CreatedAt:   "2024-01-02T00:00:00Z",
						UpdatedAt:   "2024-01-02T00:00:00Z",
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
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListEnvironmentRolesResponse{
		Data: []EnvironmentRole{
			{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Admin",
				Slug:        "admin",
				Permissions: []string{"read", "write"},
				Type:        "environment",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
			},
			{
				Object:      "role",
				Id:          "role_02DEF",
				Name:        "Viewer",
				Slug:        "viewer",
				Permissions: []string{"read"},
				Type:        "environment",
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
			client: &Client{
				APIKey: "test",
			},
			options: GetEnvironmentRoleOpts{
				Slug: "admin",
			},
			expected: EnvironmentRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Admin",
				Slug:        "admin",
				Permissions: []string{"read", "write"},
				Type:        "environment",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-01T00:00:00Z",
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
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !strings.Contains(r.URL.Path, "/authorization/roles/admin") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	body, err := json.Marshal(EnvironmentRole{
		Object:      "role",
		Id:          "role_01ABC",
		Name:        "Admin",
		Slug:        "admin",
		Permissions: []string{"read", "write"},
		Type:        "environment",
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
			client: &Client{
				APIKey: "test",
			},
			options: UpdateEnvironmentRoleOpts{
				Slug: "admin",
				Name: &updatedName,
			},
			expected: EnvironmentRole{
				Object:      "role",
				Id:          "role_01ABC",
				Name:        "Super Admin",
				Slug:        "admin",
				Permissions: []string{"read", "write"},
				Type:        "environment",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Request sets description to null",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateEnvironmentRoleOpts{
				Slug:        "admin",
				Description: nil,
			},
			expected: EnvironmentRole{
				Object:      "role",
				Id:          "role_01ABC",
				Slug:        "admin",
				Permissions: []string{"read", "write"},
				Type:        "environment",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Request updates description only",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateEnvironmentRoleOpts{
				Slug:        "admin",
				Description: stringPtr("New description"),
			},
			expected: EnvironmentRole{
				Object:      "role",
				Id:          "role_01ABC",
				Slug:        "admin",
				Description: "New description",
				Permissions: []string{"read", "write"},
				Type:        "environment",
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
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

	role := EnvironmentRole{
		Object:      "role",
		Id:          "role_01ABC",
		Slug:        "admin",
		Permissions: []string{"read", "write"},
		Type:        "environment",
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

func TestUpdateEnvironmentRoleNullDescriptionBody(t *testing.T) {
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
		w.Write([]byte(`{"object":"role","id":"role_01ABC","name":"","slug":"admin","description":"","permissions":[],"resource_type_slug":"","type":"environment","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-02T00:00:00Z"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug:        "admin",
		Description: nil,
	})
	require.NoError(t, err)
}

func stringPtr(s string) *string {
	return &s
}
