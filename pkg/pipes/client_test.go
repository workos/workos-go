package pipes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGetAccessToken(t *testing.T) {
	tests := []struct {
		scenario    string
		client      *Client
		options     GetAccessTokenOpts
		expected    AccessToken
		expectedErr error
		wantErr     bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			wantErr:  true,
		},
		{
			scenario: "Request returns active access token",
			client: &Client{
				APIKey: "test",
			},
			options: GetAccessTokenOpts{
				Provider: "salesforce",
				UserID:   "user_123",
			},
			expected: func() AccessToken {
				expiresAt := time.Date(2025, 10, 18, 12, 0, 0, 0, time.UTC)
				return AccessToken{
					AccessToken:   "test_access_token_123",
					ExpiresAt:     &expiresAt,
					Scopes:        []string{"read:users", "write:users"},
					MissingScopes: []string{},
				}
			}(),
		},
		{
			scenario: "Request returns active access token with organization_id",
			client: &Client{
				APIKey: "test",
			},
			options: GetAccessTokenOpts{
				Provider:       "salesforce",
				UserID:         "user_123",
				OrganizationID: "org_456",
			},
			expected: func() AccessToken {
				expiresAt := time.Date(2025, 10, 18, 12, 0, 0, 0, time.UTC)
				return AccessToken{
					AccessToken:   "test_access_token_123",
					ExpiresAt:     &expiresAt,
					Scopes:        []string{"read:users", "write:users"},
					MissingScopes: []string{},
				}
			}(),
		},
		{
			scenario: "Request returns access token with no expiry",
			client: &Client{
				APIKey: "test",
			},
			options: GetAccessTokenOpts{
				Provider: "no-expiry-provider",
				UserID:   "user_123",
			},
			expected: AccessToken{
				AccessToken:   "test_access_token_456",
				ExpiresAt:     nil,
				Scopes:        []string{"read:data"},
				MissingScopes: []string{"write:data"},
			},
		},
		{
			scenario: "Request returns not_installed error",
			client: &Client{
				APIKey: "test",
			},
			options: GetAccessTokenOpts{
				Provider: "not-installed-provider",
				UserID:   "user_123",
			},
			expectedErr: NotInstalled,
			wantErr:     true,
		},
		{
			scenario: "Request returns needs_reauthorization error",
			client: &Client{
				APIKey: "test",
			},
			options: GetAccessTokenOpts{
				Provider: "needs-reauth-provider",
				UserID:   "user_123",
			},
			expectedErr: NeedsReauthorization,
			wantErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getAccessTokenTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.GetAccessToken(context.Background(), test.options)
			if test.wantErr {
				require.Error(t, err)
				if test.expectedErr != nil {
					require.Equal(t, test.expectedErr, err)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func getAccessTokenTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	var response interface{}

	if strings.Contains(path, "not-installed-provider") {
		response = map[string]interface{}{
			"active": false,
			"error":  "not_installed",
		}
	} else if strings.Contains(path, "needs-reauth-provider") {
		response = map[string]interface{}{
			"active": false,
			"error":  "needs_reauthorization",
		}
	} else if strings.Contains(path, "no-expiry-provider") {
		response = map[string]interface{}{
			"active": true,
			"access_token": map[string]interface{}{
				"object":         "access_token",
				"access_token":   "test_access_token_456",
				"expires_at":     nil,
				"scopes":         []string{"read:data"},
				"missing_scopes": []string{"write:data"},
			},
		}
	} else {
		response = map[string]interface{}{
			"active": true,
			"access_token": map[string]interface{}{
				"object":         "access_token",
				"access_token":   "test_access_token_123",
				"expires_at":     "2025-10-18T12:00:00Z",
				"scopes":         []string{"read:users", "write:users"},
				"missing_scopes": []string{},
			},
		}
	}

	body, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestGetAccessTokenRequestBody(t *testing.T) {
	t.Run("with organization_id", func(t *testing.T) {
		var receivedBody struct {
			UserID         string `json:"user_id"`
			OrganizationID string `json:"organization_id,omitempty"`
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)

			response := map[string]interface{}{
				"active": true,
				"access_token": map[string]interface{}{
					"object":         "access_token",
					"access_token":   "test",
					"expires_at":     nil,
					"scopes":         []string{},
					"missing_scopes": []string{},
				},
			}
			body, _ := json.Marshal(response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		}))
		defer server.Close()

		client := &Client{
			APIKey:     "test",
			Endpoint:   server.URL,
			HTTPClient: server.Client(),
		}

		_, err := client.GetAccessToken(context.Background(), GetAccessTokenOpts{
			Provider:       "test-provider",
			UserID:         "user_123",
			OrganizationID: "org_456",
		})
		require.NoError(t, err)
		require.Equal(t, "user_123", receivedBody.UserID)
		require.Equal(t, "org_456", receivedBody.OrganizationID)
	})

	t.Run("without organization_id", func(t *testing.T) {
		var receivedBody struct {
			UserID         string `json:"user_id"`
			OrganizationID string `json:"organization_id,omitempty"`
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)

			response := map[string]interface{}{
				"active": true,
				"access_token": map[string]interface{}{
					"object":         "access_token",
					"access_token":   "test",
					"expires_at":     nil,
					"scopes":         []string{},
					"missing_scopes": []string{},
				},
			}
			body, _ := json.Marshal(response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		}))
		defer server.Close()

		client := &Client{
			APIKey:     "test",
			Endpoint:   server.URL,
			HTTPClient: server.Client(),
		}

		_, err := client.GetAccessToken(context.Background(), GetAccessTokenOpts{
			Provider: "test-provider",
			UserID:   "user_789",
		})
		require.NoError(t, err)
		require.Equal(t, "user_789", receivedBody.UserID)
		require.Equal(t, "", receivedBody.OrganizationID)
	})
}
