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

func TestCheckAuthorizedWithResourceId(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

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
}

func TestCheckAuthorizedWithResourceExternalId(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(&capturedBody)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

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
}

func TestCheckUnauthorizedWithResourceId(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

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
}

func TestCheckUnauthorizedWithResourceExternalId(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(checkUnauthorizedHandler(&capturedBody)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

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
}

func TestCheckErrorWhenResourceIdentifierIsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AccessCheckResponse{Authorized: true})
	}))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	_, err := Check(context.Background(), AuthorizationCheckOpts{
		OrganizationMembershipId: "om_01JTEST",
		PermissionSlug:           "posts:read",
		ResourceIdentifier:       nil,
	})

	require.Error(t, err)
	require.Equal(t, "ResourceIdentifier is required", err.Error())
}
