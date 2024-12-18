package roles

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRolesListRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listRolesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListRolesResponse{
		Data: []Role{
			{
				ID:          "role_01EHWNCE74X7JSDV0X3SZ3KJNY",
				Name:        "Member",
				Slug:        "member",
				Description: "The default role for all users.",
				Type:        Environment,
				CreatedAt:   "2024-12-01T00:00:00.000Z",
				UpdatedAt:   "2024-12-01T00:00:00.000Z",
			},
		},
	}

	response, err := ListRoles(context.Background(), ListRolesOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, response)
}
