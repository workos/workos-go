package permissions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
)

func TestPermissionsListPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listPermissionsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListPermissionsResponse{
		Data: []Permission{
			{
				ID:          "permission_01EHWNCE74X7JSDV0X3SZ3KJNY",
				Name:        "Manage users",
				Slug:        "users:manage",
				Description: "Manage users in the application.",
				System:      false,
				CreatedAt:   "2024-12-01T00:00:00.000Z",
				UpdatedAt:   "2024-12-01T00:00:00.000Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}

	response, err := ListPermissions(context.Background(), ListPermissionsOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, response)
}
