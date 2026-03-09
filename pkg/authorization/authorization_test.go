package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestCheckWithDefaultClient(t *testing.T) {
	t.Run("returns authorized when resource id is provided", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody)))
		defer server.Close()

		setupDefaultClient(server)

		result, err := Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})

		require.NoError(t, err)
		require.True(t, result.Authorized)
		require.Equal(t, "posts:read", capturedBody["permission_slug"])
		require.Equal(t, "res_01JTEST", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("returns authorized when resource external id is provided", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody)))
		defer server.Close()

		setupDefaultClient(server)

		result, err := Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
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
	})

	t.Run("returns unauthorized when resource id is provided", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody)))
		defer server.Close()

		setupDefaultClient(server)

		result, err := Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       ResourceIdentifierById{ResourceId: "res_01JTEST"},
		})

		require.NoError(t, err)
		require.False(t, result.Authorized)
		require.Equal(t, "posts:read", capturedBody["permission_slug"])
		require.Equal(t, "res_01JTEST", capturedBody["resource_id"])
		require.NotContains(t, capturedBody, "resource_external_id")
		require.NotContains(t, capturedBody, "resource_type_slug")
	})

	t.Run("returns unauthorized when resource external id is provided", func(t *testing.T) {
		var capturedBody map[string]interface{}

		server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody)))
		defer server.Close()

		setupDefaultClient(server)

		result, err := Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier: ResourceIdentifierByExternalId{
				ResourceExternalId: "ext_123",
				ResourceTypeSlug:   "post",
			},
		})

		require.NoError(t, err)
		require.False(t, result.Authorized)
		require.Equal(t, "posts:read", capturedBody["permission_slug"])
		require.Equal(t, "ext_123", capturedBody["resource_external_id"])
		require.Equal(t, "post", capturedBody["resource_type_slug"])
		require.NotContains(t, capturedBody, "resource_id")
	})

	t.Run("returns error when resource identifier is nil", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(nil)))
		defer server.Close()

		setupDefaultClient(server)

		_, err := Check(context.Background(), AuthorizationCheckOpts{
			OrganizationMembershipId: "om_01JTEST",
			PermissionSlug:           "posts:read",
			ResourceIdentifier:       nil,
		})

		require.Error(t, err)
		require.Equal(t, "ResourceIdentifier is required", err.Error())
	})
}

func setupDefaultClient(server *httptest.Server) {
	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")
}
