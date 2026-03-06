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
			scenario: "Request returns a Permission with all fields",
			client: &Client{
				APIKey: "test",
			},
			options: CreatePermissionOpts{
				Slug:             "documents.read",
				Name:             "Read Documents",
				Description:      "Allows reading documents",
				ResourceTypeSlug: "document",
			},
			expected: Permission{
				Object:           "permission",
				Id:               "perm_01HXYZ",
				Slug:             "documents.read",
				Name:             "Read Documents",
				Description:      "Allows reading documents",
				ResourceTypeSlug: "document",
				System:           false,
				CreatedAt:        "2024-01-01T00:00:00Z",
				UpdatedAt:        "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createPermissionTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			permission, err := client.CreatePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, permission)
		})
	}
}

func createPermissionTestHandler(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var opts CreatePermissionOpts
	json.NewDecoder(r.Body).Decode(&opts)

	body, err := json.Marshal(Permission{
		Object:           "permission",
		Id:               "perm_01HXYZ",
		Slug:             opts.Slug,
		Name:             opts.Name,
		Description:      opts.Description,
		ResourceTypeSlug: opts.ResourceTypeSlug,
		System:           false,
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(body)
}

func TestCreatePermissionWithoutOptionalFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createPermissionMinimalTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	permission, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "documents.read",
		Name: "Read Documents",
	})
	require.NoError(t, err)
	require.Equal(t, "documents.read", permission.Slug)
	require.Equal(t, "Read Documents", permission.Name)
	require.Equal(t, "", permission.Description)
	require.Equal(t, "", permission.ResourceTypeSlug)
}

func createPermissionMinimalTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	rawBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Verify optional fields were omitted from JSON
	var rawBody map[string]interface{}
	if err := json.Unmarshal(rawBytes, &rawBody); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, exists := rawBody["description"]; exists {
		http.Error(w, "unexpected field: description", http.StatusBadRequest)
		return
	}
	if _, exists := rawBody["resource_type_slug"]; exists {
		http.Error(w, "unexpected field: resource_type_slug", http.StatusBadRequest)
		return
	}

	var opts CreatePermissionOpts
	if err := json.Unmarshal(rawBytes, &opts); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      opts.Slug,
		Name:      opts.Name,
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(body)
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
			scenario: "Request returns Permissions",
			client: &Client{
				APIKey: "test",
			},
			options:  ListPermissionsOpts{},
			expected: listPermissionsExpectedResponse(),
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listPermissionsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			permissions, err := client.ListPermissions(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, permissions)
		})
	}
}

func listPermissionsExpectedResponse() ListPermissionsResponse {
	return ListPermissionsResponse{
		Data: []Permission{
			{
				Object:    "permission",
				Id:        "perm_01HXYZ",
				Slug:      "documents.read",
				Name:      "Read Documents",
				System:    false,
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
			{
				Object:    "permission",
				Id:        "perm_02HXYZ",
				Slug:      "documents.write",
				Name:      "Write Documents",
				System:    false,
				CreatedAt: "2024-01-02T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}
}

func listPermissionsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := json.Marshal(listPermissionsExpectedResponse())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListPermissionsWithPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listPermissionsPaginationTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	permissions, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
		Limit: 5,
		After: "perm_01HXYZ",
		Order: common.Asc,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(permissions.Data))
	require.Equal(t, "perm_02HXYZ", permissions.Data[0].Id)
	require.Equal(t, "perm_01HXYZ", permissions.ListMetadata.Before)
}

func listPermissionsPaginationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Verify query params are set
	q := r.URL.Query()
	if q.Get("limit") != "5" || q.Get("after") != "perm_01HXYZ" || q.Get("order") != "asc" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ListPermissionsResponse{
		Data: []Permission{
			{
				Object:    "permission",
				Id:        "perm_02HXYZ",
				Slug:      "documents.write",
				Name:      "Write Documents",
				System:    false,
				CreatedAt: "2024-01-02T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "perm_01HXYZ",
			After:  "",
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
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
			scenario: "Request returns a Permission",
			client: &Client{
				APIKey: "test",
			},
			options: GetPermissionOpts{
				Slug: "documents.read",
			},
			expected: Permission{
				Object:    "permission",
				Id:        "perm_01HXYZ",
				Slug:      "documents.read",
				Name:      "Read Documents",
				System:    false,
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getPermissionTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			permission, err := client.GetPermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, permission)
		})
	}
}

func getPermissionTestHandler(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Verify slug is in the URL path
	if !strings.HasSuffix(r.URL.Path, "/documents.read") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, err := json.Marshal(Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestUpdatePermissionName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updatePermissionTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	newName := "Read All Documents"
	permission, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "documents.read",
		Name: &newName,
	})
	require.NoError(t, err)
	require.Equal(t, "Read All Documents", permission.Name)
	require.Equal(t, "documents.read", permission.Slug)
}

func TestUpdatePermissionDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updatePermissionTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	newDesc := "Updated description"
	permission, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug:        "documents.read",
		Description: &newDesc,
	})
	require.NoError(t, err)
	require.Equal(t, "documents.read", permission.Slug)
}

func TestUpdatePermissionDescriptionToNull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updatePermissionNullDescTestHandler))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	// Sending nil pointer for Description should serialize to JSON null
	permission, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug:        "documents.read",
		Description: nil,
	})
	require.NoError(t, err)
	require.Equal(t, "", permission.Description)
}

func updatePermissionTestHandler(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var opts map[string]interface{}
	json.NewDecoder(r.Body).Decode(&opts)

	name := "Read Documents"
	if n, ok := opts["name"]; ok && n != nil {
		name = n.(string)
	}

	body, err := json.Marshal(Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      name,
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func updatePermissionNullDescTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Verify the body contains "description":null
	var raw map[string]interface{}
	json.NewDecoder(r.Body).Decode(&raw)

	// When Description is nil pointer with json tag `json:"description"` (no omitempty),
	// it should serialize as null
	if _, exists := raw["description"]; !exists {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
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
			scenario: "Request deletes a Permission",
			client: &Client{
				APIKey: "test",
			},
			options: DeletePermissionOpts{
				Slug: "documents.read",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deletePermissionTestHandler))
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

func deletePermissionTestHandler(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Verify slug is in URL path
	if !strings.HasSuffix(r.URL.Path, "/documents.read") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
