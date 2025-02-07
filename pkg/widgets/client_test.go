package widgets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetToken(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetTokenOpts
		expected string
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns widget token",
			client: &Client{
				APIKey: "test",
			},
			options: GetTokenOpts{
				OrganizationId: "organization_id",
				UserId:         "user_id",
				Scopes:         []WidgetScope{UsersTableManage},
			},
			expected: "abc123456",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getTokenTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			token, err := client.GetToken(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, token)
		})
	}
}

func getTokenTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(struct {
		GetTokenResponse
	}{GetTokenResponse{Token: "abc123456"}})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
