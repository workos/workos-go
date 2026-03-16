package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestAuthorizationCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(checkAuthorizedHandler(nil, nil)))
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
}
