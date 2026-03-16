package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestCheck(t *testing.T) {
	t.Run("returns authorized when resource id is provided", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody, &capturedPath)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "test_org_membership_id",
			PermissionSlug:           "test:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})

		require.NoError(t, err)
		require.True(t, result.Authorized)

		require.Equal(t, "/authorization/organization_memberships/test_org_membership_id/check", capturedPath)
		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "res_01JTEST", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("returns authorized when resource external id and type slug are provided", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody, &capturedPath)))
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

		require.Equal(t, "/authorization/organization_memberships/test_org_membership_id/check", capturedPath)
		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "ext_123", capturedBody["resource_external_id"])
		require.Equal(t, "post", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
	})

	t.Run("returns unauthorized when resource id is provided", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody, &capturedPath)))
		defer server.Close()

		client := newAuthorizationTestClient(server)

		result, err := client.Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "test_org_membership_id",
			PermissionSlug:           "test:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})

		require.NoError(t, err)
		require.False(t, result.Authorized)

		require.Equal(t, "/authorization/organization_memberships/test_org_membership_id/check", capturedPath)
		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "res_01JTEST", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("returns unauthorized when resource external id and type slug are provided", func(t *testing.T) {
		var capturedBody map[string]interface{}
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody, &capturedPath)))
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

		require.Equal(t, "/authorization/organization_memberships/test_org_membership_id/check", capturedPath)
		require.Equal(t, "test:read", capturedBody["permission_slug"])
		require.Equal(t, "ext_123", capturedBody["resource_external_id"])
		require.Equal(t, "post", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
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

	t.Run("returns error when API key is not provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(nil, nil)))
		defer server.Close()

		client := &Client{
			Endpoint:   server.URL,
			HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		}

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
}

func newAuthorizationTestClient(server *httptest.Server) *Client {
	return &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
}

func checkAuthorizedHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
) func(http.ResponseWriter, *http.Request) {
	return checkHandler(capturedBody, capturedPath, true)
}

func checkUnauthorizedHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
) func(http.ResponseWriter, *http.Request) {
	return checkHandler(capturedBody, capturedPath, false)
}

func checkHandler(
	capturedBody *map[string]interface{},
	capturedPath *string,
	authorized bool,
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
		_ = json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: authorized})
	}
}
