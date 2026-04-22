// @oagen-ignore-file

package workos_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v7"
)

func TestVault_CreateObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/vault/v1/kv", r.URL.Path)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var params map[string]interface{}
		err = json.Unmarshal(body, &params)
		require.NoError(t, err)
		require.Equal(t, "my-secret", params["name"])
		require.Equal(t, "secret-value", params["value"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "vault_obj_01",
			"environment_id": "env_01",
			"key_id": "key_01",
			"updated_at": "2025-01-01T00:00:00Z",
			"updated_by": "user_01",
			"version_id": "v_01",
			"context": {
				"type": "kv",
				"environment_id": "env_01"
			}
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.Vault().CreateObject(context.Background(), &workos.VaultCreateObjectParams{
		Name:  "my-secret",
		Value: "secret-value",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "vault_obj_01", result.ID)
	require.Equal(t, "env_01", result.EnvironmentID)
	require.Equal(t, "key_01", result.KeyID)
	require.Equal(t, "v_01", result.VersionID)
	require.Equal(t, "kv", result.Context.Type)
}

func TestVault_ReadObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "/vault/v1/kv/vault_obj_01", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "vault_obj_01",
			"name": "my-secret",
			"value": "secret-value",
			"metadata": {
				"id": "vault_obj_01",
				"environment_id": "env_01",
				"key_id": "key_01",
				"updated_at": "2025-01-01T00:00:00Z",
				"updated_by": "user_01",
				"version_id": "v_01",
				"context": {
					"type": "kv",
					"environment_id": "env_01"
				}
			}
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.Vault().ReadObject(context.Background(), "vault_obj_01")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "vault_obj_01", result.ID)
	require.Equal(t, "my-secret", result.Name)
	require.NotNil(t, result.Value)
	require.Equal(t, "secret-value", *result.Value)
	require.NotNil(t, result.Metadata)
	require.Equal(t, "vault_obj_01", result.Metadata.ID)
}

func TestVault_DeleteObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "DELETE", r.Method)
		require.Equal(t, "/vault/v1/kv/vault_obj_01", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	err := client.Vault().DeleteObject(context.Background(), "vault_obj_01")
	require.NoError(t, err)
}

func TestVault_DeleteObject_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found","code":"not_found"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	err := client.Vault().DeleteObject(context.Background(), "nonexistent_id")
	require.Error(t, err)
	require.IsType(t, &workos.NotFoundError{}, err)
}

func TestVault_ListObjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "/vault/v1/kv", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"data": [
				{
					"id": "vault_obj_01",
					"name": "secret-one",
					"environment_id": "env_01",
					"updated_at": "2025-01-01T00:00:00Z"
				},
				{
					"id": "vault_obj_02",
					"name": "secret-two",
					"environment_id": "env_01",
					"updated_at": "2025-01-02T00:00:00Z"
				}
			]
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.Vault().ListObjects(context.Background(), &workos.VaultListObjectsParams{})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Data, 2)
	require.Equal(t, "vault_obj_01", result.Data[0].ID)
	require.Equal(t, "secret-one", result.Data[0].Name)
	require.Equal(t, "vault_obj_02", result.Data[1].ID)
	require.Equal(t, "secret-two", result.Data[1].Name)
}
