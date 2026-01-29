package pipes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPipesGetAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"active": true,
			"access_token": map[string]interface{}{
				"object":         "access_token",
				"access_token":   "test_token",
				"expires_at":     nil,
				"scopes":         []string{"read:data"},
				"missing_scopes": []string{},
			},
		}
		body, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	DefaultClient = &Client{
		APIKey:     "test",
		Endpoint:   server.URL,
		HTTPClient: server.Client(),
	}

	response, err := GetAccessToken(context.Background(), GetAccessTokenOpts{
		Provider: "test-provider",
		UserID:   "user_123",
	})

	require.NoError(t, err)
	require.True(t, response.Active)
	require.NotNil(t, response.AccessToken)
	require.Equal(t, "test_token", response.AccessToken.AccessToken)
}

func TestSetAPIKey(t *testing.T) {
	SetAPIKey("test_api_key")
	require.Equal(t, "test_api_key", DefaultClient.APIKey)
}
