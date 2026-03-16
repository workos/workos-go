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

// -----------------------------------------------------------------------
// Permissions CRUD (fully implemented)
// -----------------------------------------------------------------------

func TestCreatePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreatePermissionOpts
		expected Permission
		err      bool
	}{
		{
			scenario: "Request without API Key returns unauthorized error",
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
		{
			scenario: "Request returns a Permission with required fields only",
			client: &Client{
				APIKey: "test",
			},
			options: CreatePermissionOpts{
				Slug: "documents.read",
				Name: "Read Documents",
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

	if r.URL.Path != "/authorization/permissions" {
		w.WriteHeader(http.StatusNotFound)
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

func TestCreatePermissionOmitsEmptyOptionalFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		var rawBody map[string]interface{}
		if err := json.Unmarshal(rawBytes, &rawBody); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// description and resource_type_slug should be omitted when empty
		if _, exists := rawBody["description"]; exists {
			http.Error(w, "unexpected field: description", http.StatusBadRequest)
			return
		}
		if _, exists := rawBody["resource_type_slug"]; exists {
			http.Error(w, "unexpected field: resource_type_slug", http.StatusBadRequest)
			return
		}

		// slug and name must be present
		if _, exists := rawBody["slug"]; !exists {
			http.Error(w, "missing field: slug", http.StatusBadRequest)
			return
		}
		if _, exists := rawBody["name"]; !exists {
			http.Error(w, "missing field: name", http.StatusBadRequest)
			return
		}

		var opts CreatePermissionOpts
		if err := json.Unmarshal(rawBytes, &opts); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		body, _ := json.Marshal(Permission{
			Object:    "permission",
			Id:        "perm_01HXYZ",
			Slug:      opts.Slug,
			Name:      opts.Name,
			System:    false,
			CreatedAt: "2024-01-01T00:00:00Z",
			UpdatedAt: "2024-01-01T00:00:00Z",
		})

		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	}))
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

func TestCreatePermissionHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"internal server error"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "documents.read",
		Name: "Read Documents",
	})
	require.Error(t, err)
}

// -----------------------------------------------------------------------
// ListPermissions
// -----------------------------------------------------------------------

func TestListPermissions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListPermissionsOpts
		expected ListPermissionsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns unauthorized error",
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

	if r.URL.Path != "/authorization/permissions" {
		w.WriteHeader(http.StatusNotFound)
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

func TestListPermissionsWithPaginationAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		if q.Get("limit") != "5" || q.Get("after") != "perm_01HXYZ" || q.Get("order") != "asc" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		body, _ := json.Marshal(ListPermissionsResponse{
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

		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
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

func TestListPermissionsWithPaginationBefore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		q := r.URL.Query()
		if q.Get("limit") != "3" || q.Get("before") != "perm_02HXYZ" || q.Get("order") != "desc" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		body, _ := json.Marshal(ListPermissionsResponse{
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
			},
			ListMetadata: common.ListMetadata{
				Before: "",
				After:  "perm_02HXYZ",
			},
		})

		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	permissions, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
		Limit:  3,
		Before: "perm_02HXYZ",
		Order:  common.Desc,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(permissions.Data))
	require.Equal(t, "perm_01HXYZ", permissions.Data[0].Id)
	require.Equal(t, "perm_02HXYZ", permissions.ListMetadata.After)
}

func TestListPermissionsDefaultLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		q := r.URL.Query()
		// When no limit is set, DefaultListSize (10) should be applied
		if q.Get("limit") != "10" {
			http.Error(w, "expected default limit of 10, got "+q.Get("limit"), http.StatusBadRequest)
			return
		}

		body, _ := json.Marshal(ListPermissionsResponse{
			Data:         []Permission{},
			ListMetadata: common.ListMetadata{},
		})

		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})
	require.NoError(t, err)
}

func TestListPermissionsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"internal server error"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})
	require.Error(t, err)
}

// -----------------------------------------------------------------------
// GetPermission
// -----------------------------------------------------------------------

func TestGetPermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetPermissionOpts
		expected Permission
		err      bool
	}{
		{
			scenario: "Request without API Key returns unauthorized error",
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

	if !strings.HasPrefix(r.URL.Path, "/authorization/permissions/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	slug := strings.TrimPrefix(r.URL.Path, "/authorization/permissions/")
	if slug != "documents.read" {
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

func TestGetPermissionURLPath(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{
			Object: "permission",
			Id:     "perm_01HXYZ",
			Slug:   "my-custom.slug",
		})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.GetPermission(context.Background(), GetPermissionOpts{
		Slug: "my-custom.slug",
	})
	require.NoError(t, err)
	require.Equal(t, "/authorization/permissions/my-custom.slug", capturedPath)
}

func TestGetPermissionHTTPNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"not found"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.GetPermission(context.Background(), GetPermissionOpts{
		Slug: "nonexistent",
	})
	require.Error(t, err)
}

// -----------------------------------------------------------------------
// UpdatePermission
// -----------------------------------------------------------------------

func TestUpdatePermission(t *testing.T) {
	newName := "Read All Documents"
	newDesc := "Updated description"

	tests := []struct {
		scenario string
		client   *Client
		options  UpdatePermissionOpts
		expected Permission
		err      bool
	}{
		{
			scenario: "Request without API Key returns unauthorized error",
			client:   &Client{},
			options: UpdatePermissionOpts{
				Slug: "documents.read",
				Name: &newName,
			},
			err: true,
		},
		{
			scenario: "Request updates name",
			client: &Client{
				APIKey: "test",
			},
			options: UpdatePermissionOpts{
				Slug: "documents.read",
				Name: &newName,
			},
			expected: Permission{
				Object:    "permission",
				Id:        "perm_01HXYZ",
				Slug:      "documents.read",
				Name:      "Read All Documents",
				System:    false,
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		{
			scenario: "Request updates description",
			client: &Client{
				APIKey: "test",
			},
			options: UpdatePermissionOpts{
				Slug:        "documents.read",
				Description: &newDesc,
			},
			expected: Permission{
				Object:      "permission",
				Id:          "perm_01HXYZ",
				Slug:        "documents.read",
				Name:        "Read Documents",
				Description: "Updated description",
				System:      false,
				CreatedAt:   "2024-01-01T00:00:00Z",
				UpdatedAt:   "2024-01-02T00:00:00Z",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updatePermissionTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			permission, err := client.UpdatePermission(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, permission)
		})
	}
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

	if !strings.HasPrefix(r.URL.Path, "/authorization/permissions/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var opts map[string]interface{}
	json.NewDecoder(r.Body).Decode(&opts)

	name := "Read Documents"
	if n, ok := opts["name"]; ok && n != nil {
		name = n.(string)
	}

	desc := ""
	if d, ok := opts["description"]; ok && d != nil {
		desc = d.(string)
	}

	body, err := json.Marshal(Permission{
		Object:      "permission",
		Id:          "perm_01HXYZ",
		Slug:        "documents.read",
		Name:        name,
		Description: desc,
		System:      false,
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-02T00:00:00Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestUpdatePermissionURLPath(t *testing.T) {
	var capturedPath string
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedMethod = r.Method
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{
			Object: "permission",
			Id:     "perm_01HXYZ",
			Slug:   "documents.read",
		})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	newName := "Updated"
	_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "documents.read",
		Name: &newName,
	})
	require.NoError(t, err)
	require.Equal(t, "/authorization/permissions/documents.read", capturedPath)
	require.Equal(t, http.MethodPatch, capturedMethod)
}

func TestUpdatePermissionDescriptionToNull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		descVal, exists := raw["description"]
		if !exists {
			http.Error(w, "description field must be present", http.StatusBadRequest)
			return
		}
		if descVal != nil {
			http.Error(w, "description field must be null", http.StatusBadRequest)
			return
		}

		body, _ := json.Marshal(Permission{
			Object:    "permission",
			Id:        "perm_01HXYZ",
			Slug:      "documents.read",
			Name:      "Read Documents",
			System:    false,
			CreatedAt: "2024-01-01T00:00:00Z",
			UpdatedAt: "2024-01-02T00:00:00Z",
		})

		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
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

func TestUpdatePermissionNameOmittedWhenNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		var raw map[string]interface{}
		json.NewDecoder(r.Body).Decode(&raw)

		// Name has omitempty, so nil pointer should not be present
		if _, exists := raw["name"]; exists {
			http.Error(w, "name field should be omitted when nil", http.StatusBadRequest)
			return
		}

		body, _ := json.Marshal(Permission{
			Object:    "permission",
			Id:        "perm_01HXYZ",
			Slug:      "documents.read",
			Name:      "Read Documents",
			System:    false,
			CreatedAt: "2024-01-01T00:00:00Z",
			UpdatedAt: "2024-01-02T00:00:00Z",
		})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	// Name is nil, should be omitted from JSON body
	permission, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "documents.read",
		Name: nil,
	})
	require.NoError(t, err)
	require.Equal(t, "Read Documents", permission.Name)
}

func TestUpdatePermissionHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"internal server error"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	newName := "Updated"
	_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
		Slug: "documents.read",
		Name: &newName,
	})
	require.Error(t, err)
}

// -----------------------------------------------------------------------
// DeletePermission
// -----------------------------------------------------------------------

func TestDeletePermission(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeletePermissionOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns unauthorized error",
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

	if !strings.HasPrefix(r.URL.Path, "/authorization/permissions/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	slug := strings.TrimPrefix(r.URL.Path, "/authorization/permissions/")
	if slug != "documents.read" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func TestDeletePermissionURLPath(t *testing.T) {
	var capturedPath string
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedMethod = r.Method
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeletePermission(context.Background(), DeletePermissionOpts{
		Slug: "my-permission",
	})
	require.NoError(t, err)
	require.Equal(t, "/authorization/permissions/my-permission", capturedPath)
	require.Equal(t, http.MethodDelete, capturedMethod)
}

func TestDeletePermissionHTTPNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"not found"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeletePermission(context.Background(), DeletePermissionOpts{
		Slug: "nonexistent",
	})
	require.Error(t, err)
}

func TestDeletePermissionHTTPServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"internal server error"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeletePermission(context.Background(), DeletePermissionOpts{
		Slug: "documents.read",
	})
	require.Error(t, err)
}

// -----------------------------------------------------------------------
// CreatePermission request body verification
// -----------------------------------------------------------------------

func TestCreatePermissionRequestBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		rawBytes, _ := io.ReadAll(r.Body)
		var rawBody map[string]interface{}
		json.Unmarshal(rawBytes, &rawBody)

		// Verify JSON field names match the expected wire format
		require.Equal(t, "documents.read", rawBody["slug"])
		require.Equal(t, "Read Documents", rawBody["name"])
		require.Equal(t, "Allows reading documents", rawBody["description"])
		require.Equal(t, "document", rawBody["resource_type_slug"])

		body, _ := json.Marshal(Permission{
			Object:           "permission",
			Id:               "perm_01HXYZ",
			Slug:             "documents.read",
			Name:             "Read Documents",
			Description:      "Allows reading documents",
			ResourceTypeSlug: "document",
			CreatedAt:        "2024-01-01T00:00:00Z",
			UpdatedAt:        "2024-01-01T00:00:00Z",
		})
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
		Slug:             "documents.read",
		Name:             "Read Documents",
		Description:      "Allows reading documents",
		ResourceTypeSlug: "document",
	})
	require.NoError(t, err)
}

// -----------------------------------------------------------------------
// Environment Roles (stubs -- verify "not implemented")
// -----------------------------------------------------------------------

func TestCreateEnvironmentRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.CreateEnvironmentRole(context.Background(), CreateEnvironmentRoleOpts{
		Slug:             "admin",
		Name:             "Admin",
		Description:      "Administrator role",
		ResourceTypeSlug: "organization",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListEnvironmentRoles(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListEnvironmentRoles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetEnvironmentRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.GetEnvironmentRole(context.Background(), GetEnvironmentRoleOpts{
		Slug: "admin",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateEnvironmentRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	newName := "Super Admin"
	_, err := client.UpdateEnvironmentRole(context.Background(), UpdateEnvironmentRoleOpts{
		Slug: "admin",
		Name: &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Organization Roles (stubs)
// -----------------------------------------------------------------------

func TestCreateOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.CreateOrganizationRole(context.Background(), CreateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Name:           "Editor",
		Description:    "Can edit resources",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListOrganizationRoles(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationId: "org_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.GetOrganizationRole(context.Background(), GetOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	newName := "Senior Editor"
	_, err := client.UpdateOrganizationRole(context.Background(), UpdateOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Name:           &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteOrganizationRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.DeleteOrganizationRole(context.Background(), DeleteOrganizationRoleOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Role Permissions (stubs)
// -----------------------------------------------------------------------

func TestSetEnvironmentRolePermissions(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.SetEnvironmentRolePermissions(context.Background(), SetEnvironmentRolePermissionsOpts{
		Slug:        "admin",
		Permissions: []string{"documents.read", "documents.write"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddEnvironmentRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.AddEnvironmentRolePermission(context.Background(), AddEnvironmentRolePermissionOpts{
		Slug:           "admin",
		PermissionSlug: "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestSetOrganizationRolePermissions(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.SetOrganizationRolePermissions(context.Background(), SetOrganizationRolePermissionsOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		Permissions:    []string{"documents.read", "documents.write"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAddOrganizationRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.AddOrganizationRolePermission(context.Background(), AddOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		PermissionSlug: "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveOrganizationRolePermission(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.RemoveOrganizationRolePermission(context.Background(), RemoveOrganizationRolePermissionOpts{
		OrganizationId: "org_01ABC",
		Slug:           "editor",
		PermissionSlug: "documents.read",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Resources (stubs)
// -----------------------------------------------------------------------

func TestGetResource(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.GetResource(context.Background(), GetAuthorizationResourceOpts{
		ResourceId: "res_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreateResource(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_doc_123",
		Name:             "Test Document",
		Description:      "A test document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreateResourceWithParentById(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_doc_456",
		Name:             "Child Document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01ABC",
		Parent:           ParentResourceIdentifierById{ParentResourceId: "res_parent_01"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCreateResourceWithParentByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.CreateResource(context.Background(), CreateAuthorizationResourceOpts{
		ExternalId:       "ext_doc_789",
		Name:             "Nested Document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01ABC",
		Parent: ParentResourceIdentifierByExternalId{
			ParentResourceExternalId: "ext_folder_1",
			ParentResourceTypeSlug:   "folder",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateResource(t *testing.T) {
	client := &Client{APIKey: "test"}

	newName := "Updated Document"
	_, err := client.UpdateResource(context.Background(), UpdateAuthorizationResourceOpts{
		ResourceId: "res_01ABC",
		Name:       &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResource(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId: "res_01ABC",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResourceWithCascade(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.DeleteResource(context.Background(), DeleteAuthorizationResourceOpts{
		ResourceId:    "res_01ABC",
		CascadeDelete: true,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListResources(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		Limit:            10,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListResourcesWithFilters(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListResources(context.Background(), ListAuthorizationResourcesOpts{
		OrganizationId:         "org_01ABC",
		ResourceTypeSlug:       "document",
		ParentResourceId:       "res_parent_01",
		ParentResourceTypeSlug: "folder",
		Search:                 "test",
		Limit:                  5,
		After:                  "res_cursor",
		Order:                  common.Desc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestGetResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestUpdateResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	newName := "Updated Via External"
	_, err := client.UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
		Name:             &newName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestDeleteResourceByExternalIdWithCascade(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
		CascadeDelete:    true,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Authorization Check (stub)
// -----------------------------------------------------------------------

func TestCheckWithResourceById(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "documents.read",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01XYZ"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestCheckWithResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "documents.read",
		Resource: ResourceIdentifierByExternalId{
			ResourceExternalId: "ext_doc_123",
			ResourceTypeSlug:   "document",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Role Assignments (stubs)
// -----------------------------------------------------------------------

func TestListRoleAssignments(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01ABC",
		Limit:                    10,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListRoleAssignmentsWithPagination(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01ABC",
		Limit:                    5,
		After:                    "ra_cursor",
		Order:                    common.Asc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAssignRoleWithResourceById(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "editor",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01XYZ"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestAssignRoleWithResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "editor",
		Resource: ResourceIdentifierByExternalId{
			ResourceExternalId: "ext_doc_123",
			ResourceTypeSlug:   "document",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveRole(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "editor",
		Resource:                 ResourceIdentifierById{ResourceId: "res_01XYZ"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestRemoveRoleAssignment(t *testing.T) {
	client := &Client{APIKey: "test"}

	err := client.RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleAssignmentId:         "ra_01XYZ",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// Membership / Resource queries (stubs)
// -----------------------------------------------------------------------

func TestListResourcesForMembership(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "documents.read",
		Limit:                    10,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListResourcesForMembershipWithParentById(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "documents.read",
		ParentResource:           ParentResourceIdentifierById{ParentResourceId: "res_parent_01"},
		Limit:                    5,
		After:                    "res_cursor",
		Order:                    common.Desc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListResourcesForMembershipWithParentByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListResourcesForMembership(context.Background(), ListResourcesForMembershipOpts{
		OrganizationMembershipId: "om_01ABC",
		PermissionSlug:           "documents.read",
		ParentResource: ParentResourceIdentifierByExternalId{
			ParentResourceExternalId: "ext_folder_1",
			ParentResourceTypeSlug:   "folder",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResource(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "res_01XYZ",
		PermissionSlug: "documents.read",
		Limit:          10,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResourceWithAssignment(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListMembershipsForResource(context.Background(), ListMembershipsForResourceOpts{
		ResourceId:     "res_01XYZ",
		PermissionSlug: "documents.read",
		Assignment:     "direct",
		Limit:          5,
		After:          "om_cursor",
		Order:          common.Asc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResourceByExternalId(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
		PermissionSlug:   "documents.read",
		Limit:            10,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestListMembershipsForResourceByExternalIdWithFilters(t *testing.T) {
	client := &Client{APIKey: "test"}

	_, err := client.ListMembershipsForResourceByExternalId(context.Background(), ListMembershipsForResourceByExternalIdOpts{
		OrganizationId:   "org_01ABC",
		ResourceTypeSlug: "document",
		ExternalId:       "ext_doc_123",
		PermissionSlug:   "documents.read",
		Assignment:       "inherited",
		Limit:            5,
		Before:           "om_cursor",
		Order:            common.Desc,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

// -----------------------------------------------------------------------
// ResourceIdentifier interface tests
// -----------------------------------------------------------------------

func TestResourceIdentifierById(t *testing.T) {
	id := ResourceIdentifierById{ResourceId: "res_01ABC"}
	params := id.resourceIdentifierParams()
	require.Equal(t, "res_01ABC", params["resource_id"])
	require.Len(t, params, 1)
}

func TestResourceIdentifierByExternalId(t *testing.T) {
	id := ResourceIdentifierByExternalId{
		ResourceExternalId: "ext_doc_123",
		ResourceTypeSlug:   "document",
	}
	params := id.resourceIdentifierParams()
	require.Equal(t, "ext_doc_123", params["resource_external_id"])
	require.Equal(t, "document", params["resource_type_slug"])
	require.Len(t, params, 2)
}

func TestParentResourceIdentifierById(t *testing.T) {
	id := ParentResourceIdentifierById{ParentResourceId: "res_parent_01"}
	params := id.parentResourceIdentifierParams()
	require.Equal(t, "res_parent_01", params["parent_resource_id"])
	require.Len(t, params, 1)
}

func TestParentResourceIdentifierByExternalId(t *testing.T) {
	id := ParentResourceIdentifierByExternalId{
		ParentResourceExternalId: "ext_folder_1",
		ParentResourceTypeSlug:   "folder",
	}
	params := id.parentResourceIdentifierParams()
	require.Equal(t, "ext_folder_1", params["parent_resource_external_id"])
	require.Equal(t, "folder", params["parent_resource_type_slug"])
	require.Len(t, params, 2)
}

// -----------------------------------------------------------------------
// Client init defaults
// -----------------------------------------------------------------------

func TestClientInitDefaults(t *testing.T) {
	client := &Client{}
	client.init()

	require.NotNil(t, client.HTTPClient)
	require.Equal(t, "https://api.workos.com", client.Endpoint)
	require.NotNil(t, client.JSONEncode)
}

func TestClientInitPreservesCustomValues(t *testing.T) {
	customHTTP := &retryablehttp.HttpClient{}
	customEndpoint := "https://custom.api.workos.com"
	customEncode := func(v interface{}) ([]byte, error) { return nil, nil }

	client := &Client{
		HTTPClient: customHTTP,
		Endpoint:   customEndpoint,
		JSONEncode: customEncode,
	}
	client.init()

	require.Equal(t, customHTTP, client.HTTPClient)
	require.Equal(t, customEndpoint, client.Endpoint)
	require.NotNil(t, client.JSONEncode)
}

// -----------------------------------------------------------------------
// User-Agent header verification
// -----------------------------------------------------------------------

func TestCreatePermissionUserAgentHeader(t *testing.T) {
	var capturedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{Object: "permission", Id: "perm_01HXYZ", Slug: "test"})
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
		Slug: "test",
		Name: "Test",
	})
	require.NoError(t, err)
	require.Contains(t, capturedUserAgent, "workos-go/")
}

func TestListPermissionsUserAgentHeader(t *testing.T) {
	var capturedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(ListPermissionsResponse{Data: []Permission{}, ListMetadata: common.ListMetadata{}})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})
	require.NoError(t, err)
	require.Contains(t, capturedUserAgent, "workos-go/")
}

func TestGetPermissionUserAgentHeader(t *testing.T) {
	var capturedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{Object: "permission", Id: "perm_01HXYZ", Slug: "test"})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.GetPermission(context.Background(), GetPermissionOpts{Slug: "test"})
	require.NoError(t, err)
	require.Contains(t, capturedUserAgent, "workos-go/")
}

func TestUpdatePermissionUserAgentHeader(t *testing.T) {
	var capturedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{Object: "permission", Id: "perm_01HXYZ", Slug: "test"})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	newName := "Updated"
	_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{Slug: "test", Name: &newName})
	require.NoError(t, err)
	require.Contains(t, capturedUserAgent, "workos-go/")
}

func TestDeletePermissionUserAgentHeader(t *testing.T) {
	var capturedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeletePermission(context.Background(), DeletePermissionOpts{Slug: "test"})
	require.NoError(t, err)
	require.Contains(t, capturedUserAgent, "workos-go/")
}

// -----------------------------------------------------------------------
// HTTP method verification
// -----------------------------------------------------------------------

func TestCreatePermissionUsesPostMethod(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{Object: "permission", Id: "perm_01HXYZ", Slug: "test"})
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{Slug: "test", Name: "Test"})
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, capturedMethod)
}

func TestListPermissionsUsesGetMethod(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(ListPermissionsResponse{Data: []Permission{}, ListMetadata: common.ListMetadata{}})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, capturedMethod)
}

func TestGetPermissionUsesGetMethod(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{Object: "permission", Id: "perm_01HXYZ", Slug: "test"})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.GetPermission(context.Background(), GetPermissionOpts{Slug: "test"})
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, capturedMethod)
}

func TestUpdatePermissionUsesPatchMethod(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(Permission{Object: "permission", Id: "perm_01HXYZ", Slug: "test"})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	newName := "Updated"
	_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{Slug: "test", Name: &newName})
	require.NoError(t, err)
	require.Equal(t, http.MethodPatch, capturedMethod)
}

func TestDeletePermissionUsesDeleteMethod(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		if r.Header.Get("Authorization") != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	err := client.DeletePermission(context.Background(), DeletePermissionOpts{Slug: "test"})
	require.NoError(t, err)
	require.Equal(t, http.MethodDelete, capturedMethod)
}
