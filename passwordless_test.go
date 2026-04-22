// @oagen-ignore-file

package workos_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6"
)

func TestPasswordless_CreateSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/passwordless/sessions", r.URL.Path)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var params map[string]interface{}
		err = json.Unmarshal(body, &params)
		require.NoError(t, err)
		require.Equal(t, "test@example.com", params["email"])
		require.Equal(t, "MagicLink", params["type"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "passwordless_session_01",
			"email": "test@example.com",
			"expires_at": "2025-01-01T00:00:00Z",
			"link": "https://auth.workos.com/passwordless/token/confirm",
			"object": "passwordless_session"
		}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.Passwordless().CreateSession(context.Background(), &workos.PasswordlessCreateSessionParams{
		Email: "test@example.com",
		Type:  workos.PasswordlessSessionTypeMagicLink,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "passwordless_session_01", result.ID)
	require.Equal(t, "test@example.com", result.Email)
	require.Equal(t, "https://auth.workos.com/passwordless/token/confirm", result.Link)
	require.Equal(t, "passwordless_session", result.Object)
}

func TestPasswordless_CreateSession_WithOptionalParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var params map[string]interface{}
		err = json.Unmarshal(body, &params)
		require.NoError(t, err)
		require.Equal(t, "https://example.com/callback", params["redirect_uri"])
		require.Equal(t, "custom_state", params["state"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "passwordless_session_02",
			"email": "user@example.com",
			"expires_at": "2025-01-01T00:00:00Z",
			"link": "https://auth.workos.com/passwordless/token/confirm",
			"object": "passwordless_session"
		}`))
	}))
	defer server.Close()

	redirectURI := "https://example.com/callback"
	state := "custom_state"

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.Passwordless().CreateSession(context.Background(), &workos.PasswordlessCreateSessionParams{
		Email:       "user@example.com",
		Type:        workos.PasswordlessSessionTypeMagicLink,
		RedirectURI: &redirectURI,
		State:       &state,
	})
	require.NoError(t, err)
	require.Equal(t, "passwordless_session_02", result.ID)
}

func TestPasswordless_SendSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/passwordless/sessions/passwordless_session_01/send", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	err := client.Passwordless().SendSession(context.Background(), "passwordless_session_01")
	require.NoError(t, err)
}

func TestPasswordless_SendSession_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found","code":"not_found"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	err := client.Passwordless().SendSession(context.Background(), "nonexistent_id")
	require.Error(t, err)
	require.IsType(t, &workos.NotFoundError{}, err)
}
