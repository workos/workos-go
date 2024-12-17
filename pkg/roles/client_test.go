package roles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListRoles(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListRolesOpts
		expected ListRolesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns list of roles",
			client: &Client{
				APIKey: "test",
			},
			options: ListRolesOpts{},
			expected: ListRolesResponse{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listRolesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.ListRoles(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func listRolesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(struct {
		ListRolesResponse
	}{ListRolesResponse{
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
	}})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
