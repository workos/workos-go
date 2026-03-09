package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestCheck(t *testing.T) {
	t.Run("returns authorized with resource id", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "test_org_membership_id",
			PermissionSlug:           "test:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})

		require.NoError(t, err)
		require.True(t, result.Authorized)

		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "res_01JTEST", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("returns authorized with resource external id", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "test_org_membership_id",
			PermissionSlug:           "test:read",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext_123",
				ResourceTypeSlug:   "post",
			},
		})

		require.NoError(t, err)
		require.True(t, result.Authorized)

		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "ext_123", capturedBody["resource_external_id"])
		require.Equal(t, "post", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
	})

	t.Run("returns unauthorized with resource id", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "test_org_membership_id",
			PermissionSlug:           "test:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})

		require.NoError(t, err)
		require.False(t, result.Authorized)

		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "res_01JTEST", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("returns unauthorized with resource external id", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "test_org_membership_id",
			PermissionSlug:           "test:read",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext_123",
				ResourceTypeSlug:   "post",
			},
		})

		require.NoError(t, err)
		require.False(t, result.Authorized)

		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "ext_123", capturedBody["resource_external_id"])
		require.Equal(t, "post", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
	})

	t.Run("uses organization membership id in url path", func(t *testing.T) {
		orgMembershipId := "test_org_membership_id"
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedPathHandler(&capturedPath)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: orgMembershipId,
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})
		require.NoError(t, err)
		require.Equal(t, "/authorization/organization_memberships/test_org_membership_id/check", capturedPath)
	})

	t.Run("returns error when endpoint returns http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})
		require.Error(t, err)
	})

	t.Run("returns error when resource identifier is nil", func(t *testing.T) {
		client := &Client{
			APIKey:   "test",
			Endpoint: "http://localhost",
		}

		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       nil,
		})
		require.Error(t, err)
		require.Equal(t, "ResourceIdentifier is required", err.Error())
	})

	t.Run("sends correct request headers", func(t *testing.T) {
		var capturedHeaders http.Header

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeaders = r.Header.Clone()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: true})
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})
		require.NoError(t, err)

		require.Equal(t, "application/json", capturedHeaders.Get("Content-Type"))
		require.Equal(t, "Bearer test", capturedHeaders.Get("Authorization"))
		require.True(t,
			strings.HasPrefix(capturedHeaders.Get("User-Agent"), "workos-go/"),
			fmt.Sprintf("expected User-Agent to start with 'workos-go/', got %q", capturedHeaders.Get("User-Agent")),
		)
	})

	t.Run("returns error when response body is invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not json"))
		}))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})
		require.Error(t, err)
	})

	t.Run("returns error when organization membership id is empty", func(t *testing.T) {
		client := &Client{
			APIKey:   "test",
			Endpoint: "http://localhost",
		}

		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})
		require.Error(t, err)
		require.Equal(t, "OrganizationMembershipId is required", err.Error())
	})

	t.Run("returns error when permission slug is empty", func(t *testing.T) {
		client := &Client{
			APIKey:   "test",
			Endpoint: "http://localhost",
		}

		_, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})
		require.Error(t, err)
		require.Equal(t, "PermissionSlug is required", err.Error())
	})
}

func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

func checkAuthorizedHandler(capturedBody *map[string]interface{}) func(http.ResponseWriter, *http.Request) {
	return checkHandler(capturedBody, true)
}

func checkUnauthorizedHandler(capturedBody *map[string]interface{}) func(http.ResponseWriter, *http.Request) {
	return checkHandler(capturedBody, false)
}

func checkHandler(capturedBody *map[string]interface{}, authorized bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
		_ = json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: authorized})
	}
}

func checkAuthorizedPathHandler(capturedPath *string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		*capturedPath = r.URL.Path

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: true})
	}
}
