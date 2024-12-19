package permissions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
)

func TestListPermissions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListPermissionsOpts
		expected ListPermissionsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns list of permissions",
			client: &Client{
				APIKey: "test",
			},
			options: ListPermissionsOpts{},
			expected: ListPermissionsResponse{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listPermissionsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.ListPermissions(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func listPermissionsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(struct {
		ListPermissionsResponse
	}{ListPermissionsResponse{
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
	}})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
