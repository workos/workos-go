package authorization

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestCheckWithResourceById(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
			http.Error(w, "failed to decode body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: true})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	result, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01JTEST",
		PermissionSlug:           "test:read",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
	})
	require.NoError(t, err)
	require.True(t, result.Authorized)

	require.Equal(t, "test:read", capturedBody["permission_slug"])
	require.Equal(t, "res_01JTEST", capturedBody["resource_id"])
	require.NotContains(t, capturedBody, "resource_external_id")
	require.NotContains(t, capturedBody, "resource_type_slug")
}

func TestCheckWithResourceByExternalId(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
			http.Error(w, "failed to decode body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: true})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	result, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01JTEST",
		PermissionSlug:           "test:read",
		ResourceIdentifier: ResourceIdentifierByExternalId{
			ResourceExternalId: "ext_123",
			ResourceTypeSlug:   "post",
		},
	})
	require.NoError(t, err)
	require.True(t, result.Authorized)

	require.Equal(t, "posts:read", capturedBody["permission_slug"])
	require.Equal(t, "ext_123", capturedBody["resource_external_id"])
	require.Equal(t, "post", capturedBody["resource_type_slug"])
	require.NotContains(t, capturedBody, "resource_id")
}

func TestCheckReturnsUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: false})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	result, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01JTEST",
		PermissionSlug:           "posts:delete",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
	})
	require.NoError(t, err)
	require.False(t, result.Authorized)
}

func TestCheckURLContainsMembershipId(t *testing.T) {
	membershipId := "om_01JSPECIFIC"
	var capturedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: true})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: membershipId,
		PermissionSlug:           "posts:read",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
	})
	require.NoError(t, err)
	require.Equal(t, "/authorization/organization_memberships/"+membershipId+"/check", capturedPath)
}

func TestCheckHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	_, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01JTEST",
		PermissionSlug:           "posts:read",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
	})
	require.Error(t, err)
}

func TestCheckWithNilResource(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
			http.Error(w, "failed to decode body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: true})
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}

	result, err := client.Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01JTEST",
		PermissionSlug:           "posts:read",
		ResourceIdentifier:       nil,
	})
	require.NoError(t, err)
	require.True(t, result.Authorized)

	require.Len(t, capturedBody, 1)
	require.Equal(t, "posts:read", capturedBody["permission_slug"])
}
