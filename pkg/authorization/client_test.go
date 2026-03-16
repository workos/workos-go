package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestCreatePermission(t *testing.T) {
	allFieldsResponse := Permission{
		Object:           "permission",
		Id:               "perm_01HXYZ",
		Slug:             "documents.read",
		Name:             "Read Documents",
		Description:      "Allows reading documents",
		ResourceTypeSlug: "document",
		System:           false,
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	}

	requiredFieldsResponse := Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}

	noDescriptionResponse := Permission{
		Object:           "permission",
		Id:               "perm_01HXYZ",
		Slug:             "documents.read",
		Name:             "Read Documents",
		ResourceTypeSlug: "document",
		System:           false,
		CreatedAt:        "2024-01-01T00:00:00Z",
		UpdatedAt:        "2024-01-01T00:00:00Z",
	}

	t.Run("create permission with all fields", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, allFieldsResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permission, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
			Slug:             "documents.read",
			Name:             "Read Documents",
			Description:      "Allows reading documents",
			ResourceTypeSlug: "document",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/permissions", capturedPath)
		require.Equal(t, "documents.read", capturedBody["slug"])
		require.Equal(t, "Read Documents", capturedBody["name"])
		require.Equal(t, "Allows reading documents", capturedBody["description"])
		require.Equal(t, "document", capturedBody["resource_type_slug"])
		require.Equal(t, allFieldsResponse, permission)
	})

	t.Run("create permission with required fields only", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(nil, nil, requiredFieldsResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permission, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
			Slug: "documents.read",
			Name: "Read Documents",
		})

		require.NoError(t, err)
		require.Equal(t, requiredFieldsResponse, permission)
		require.Equal(t, "", permission.Description)
		require.Equal(t, "", permission.ResourceTypeSlug)
	})

	t.Run("create permission with no description", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(nil, nil, noDescriptionResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permission, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
			Slug:             "documents.read",
			Name:             "Read Documents",
			ResourceTypeSlug: "document",
		})

		require.NoError(t, err)
		require.Equal(t, noDescriptionResponse, permission)
		require.Equal(t, "", permission.Description)
		require.Equal(t, "document", permission.ResourceTypeSlug)
	})

	t.Run("create permission with no resource type slug", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(nil, nil, requiredFieldsResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permission, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
			Slug: "documents.read",
			Name: "Read Documents",
		})

		require.NoError(t, err)
		require.Equal(t, requiredFieldsResponse, permission)
		require.Equal(t, "", permission.Description)
		require.Equal(t, "", permission.ResourceTypeSlug)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.CreatePermission(context.Background(), CreatePermissionOpts{
			Slug: "documents.read",
			Name: "Read Documents",
		})

		require.Error(t, err)
	})
}

func TestListPermissions(t *testing.T) {
	permissionA := Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}

	permissionB := Permission{
		Object:    "permission",
		Id:        "perm_02HXYZ",
		Slug:      "documents.write",
		Name:      "Write Documents",
		System:    false,
		CreatedAt: "2024-01-02T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	}

	twoItemResponse := ListPermissionsResponse{
		Data: []Permission{permissionA, permissionB},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}

	emptyResponse := ListPermissionsResponse{
		Data:         []Permission{},
		ListMetadata: common.ListMetadata{},
	}

	t.Run("returns permissions", func(t *testing.T) {
		var capturedPath string
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(&capturedPath, &capturedRawQuery, twoItemResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permissions, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})

		require.NoError(t, err)
		require.Equal(t, "/authorization/permissions", capturedPath)
		require.Equal(t, 2, len(permissions.Data))
		require.Equal(t, twoItemResponse, permissions)
	})

	t.Run("returns empty list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, nil, emptyResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permissions, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})

		require.NoError(t, err)
		require.Equal(t, 0, len(permissions.Data))
	})

	t.Run("applies default limit when none specified", func(t *testing.T) {
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, &capturedRawQuery, emptyResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "limit=10")
	})

	t.Run("passes order asc", func(t *testing.T) {
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, &capturedRawQuery, emptyResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
			Order: common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=asc")
	})

	t.Run("passes order desc", func(t *testing.T) {
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, &capturedRawQuery, emptyResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
			Order: common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "order=desc")
	})

	t.Run("passes custom limit", func(t *testing.T) {
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, &capturedRawQuery, emptyResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
			Limit: 5,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "limit=5")
	})

	t.Run("passes after cursor", func(t *testing.T) {
		var capturedRawQuery string

		afterResponse := ListPermissionsResponse{
			Data: []Permission{permissionB},
			ListMetadata: common.ListMetadata{
				Before: "perm_01HXYZ",
				After:  "",
			},
		}

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, &capturedRawQuery, afterResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permissions, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
			Limit: 5,
			After: "perm_01HXYZ",
			Order: common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "after=perm_01HXYZ")
		require.NotContains(t, capturedRawQuery, "before=")
		require.Equal(t, 1, len(permissions.Data))
		require.Equal(t, "perm_02HXYZ", permissions.Data[0].Id)
		require.Equal(t, "perm_01HXYZ", permissions.ListMetadata.Before)
	})

	t.Run("passes before cursor", func(t *testing.T) {
		var capturedRawQuery string

		beforeResponse := ListPermissionsResponse{
			Data: []Permission{permissionA},
			ListMetadata: common.ListMetadata{
				Before: "",
				After:  "perm_02HXYZ",
			},
		}

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, &capturedRawQuery, beforeResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permissions, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
			Limit:  3,
			Before: "perm_02HXYZ",
			Order:  common.Desc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "before=perm_02HXYZ")
		require.NotContains(t, capturedRawQuery, "after=")
		require.Equal(t, 1, len(permissions.Data))
		require.Equal(t, "perm_01HXYZ", permissions.Data[0].Id)
		require.Equal(t, "perm_02HXYZ", permissions.ListMetadata.After)
	})

	t.Run("passes all parameters", func(t *testing.T) {
		var capturedRawQuery string

		server := httptest.NewServer(http.HandlerFunc(
			listResponseHandler(nil, &capturedRawQuery, emptyResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{
			Limit: 7,
			After: "perm_cursor",
			Order: common.Asc,
		})

		require.NoError(t, err)
		require.Contains(t, capturedRawQuery, "limit=7")
		require.Contains(t, capturedRawQuery, "after=perm_cursor")
		require.Contains(t, capturedRawQuery, "order=asc")
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.ListPermissions(context.Background(), ListPermissionsOpts{})

		require.Error(t, err)
	})
}

func TestGetPermission(t *testing.T) {
	expectedPermission := Permission{
		Object:    "permission",
		Id:        "perm_01HXYZ",
		Slug:      "documents.read",
		Name:      "Read Documents",
		System:    false,
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}

	t.Run("returns permission", func(t *testing.T) {
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(nil, &capturedPath, expectedPermission),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		permission, err := client.GetPermission(context.Background(), GetPermissionOpts{
			Slug: "documents.read",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/permissions/documents.read", capturedPath)
		require.Equal(t, expectedPermission, permission)
	})

	t.Run("returns error when not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"not found"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		_, err := client.GetPermission(context.Background(), GetPermissionOpts{
			Slug: "nonexistent",
		})

		require.Error(t, err)
	})
}

func TestUpdatePermission(t *testing.T) {
	t.Run("updates name", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		expectedResponse := Permission{
			Object:    "permission",
			Id:        "perm_01HXYZ",
			Slug:      "documents.read",
			Name:      "Read All Documents",
			System:    false,
			CreatedAt: "2024-01-01T00:00:00Z",
			UpdatedAt: "2024-01-02T00:00:00Z",
		}

		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, &capturedPath, expectedResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		newName := "Read All Documents"
		permission, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
			Slug: "documents.read",
			Name: &newName,
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/permissions/documents.read", capturedPath)
		require.Equal(t, "Read All Documents", capturedBody["name"])
		require.NotContains(t, capturedBody, "description")
		require.Equal(t, expectedResponse, permission)
	})

	t.Run("updates description", func(t *testing.T) {
		var capturedBody map[string]interface{}

		expectedResponse := Permission{
			Object:      "permission",
			Id:          "perm_01HXYZ",
			Slug:        "documents.read",
			Name:        "Read Documents",
			Description: "Updated description",
			System:      false,
			CreatedAt:   "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-02T00:00:00Z",
		}

		server := httptest.NewServer(http.HandlerFunc(
			jsonResponseHandler(&capturedBody, nil, expectedResponse),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		newDesc := "Updated description"
		permission, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
			Slug:        "documents.read",
			Description: &newDesc,
		})

		require.NoError(t, err)
		require.Equal(t, "Updated description", capturedBody["description"])
		require.Equal(t, expectedResponse, permission)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		newName := "Updated"
		_, err := client.UpdatePermission(context.Background(), UpdatePermissionOpts{
			Slug: "documents.read",
			Name: &newName,
		})

		require.Error(t, err)
	})
}

func TestDeletePermission(t *testing.T) {
	t.Run("deletes permission", func(t *testing.T) {
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(
			noContentHandler(nil, &capturedPath),
		))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeletePermission(context.Background(), DeletePermissionOpts{
			Slug: "my-permission",
		})

		require.NoError(t, err)
		require.Equal(t, "/authorization/permissions/my-permission", capturedPath)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"internal server error"}`))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)
		err := client.DeletePermission(context.Background(), DeletePermissionOpts{
			Slug: "documents.read",
		})

		require.Error(t, err)
	})
}

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

// Shared test helpers

func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

func jsonResponseHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
	response interface{},
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		if capturedBody != nil {
			if err := json.NewDecoder(r.Body).Decode(capturedBody); err != nil {
				http.Error(w, "failed to decode body", http.StatusBadRequest)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}
}

func listResponseHandler(
	capturedPath *string,
	capturedRawQuery *string,
	response interface{},
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}
		if capturedRawQuery != nil {
			*capturedRawQuery = r.URL.RawQuery
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}
}

func noContentHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		if capturedBody != nil {
			if err := json.NewDecoder(r.Body).Decode(capturedBody); err != nil {
				http.Error(w, "failed to decode body", http.StatusBadRequest)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
