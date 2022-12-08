package passwordless

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateSession(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateSessionOpts
		expected PasswordlessSession
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns PasswordlessSession",
			client: &Client{
				APIKey: "test",
			},
			options: CreateSessionOpts{
				Email:       "sasa@foo-corp.com",
				Type:        MagicLink,
				RedirectURI: "https://example.com/passwordless/callback",
			},
			expected: PasswordlessSession{
				ID:        "session_id",
				Email:     "sasa@foo-corp.com",
				ExpiresAt: "",
				Link:      "https://id.workos.test/passwordless/1234/confirm",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createSessionTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			session, err := client.CreateSession(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, session)
		})
	}
}

func createSessionTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var opts CreateSessionOpts
	json.NewDecoder(r.Body).Decode(&opts)

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(
		PasswordlessSession{
			ID:        "session_id",
			Email:     "sasa@foo-corp.com",
			ExpiresAt: "",
			Link:      "https://id.workos.test/passwordless/1234/confirm",
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestSendSession(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  SendSessionOpts
		expected string
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Session is sent",
			client: &Client{
				APIKey: "test",
			},
			options: SendSessionOpts{
				SessionID: "session_id",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(sendSessionTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.SendSession(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func sendSessionTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}
