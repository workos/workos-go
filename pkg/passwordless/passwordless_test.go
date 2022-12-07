package passwordless

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordlessCreateSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createSessionTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse :=
		PasswordlessSession{
			ID:        "session_id",
			Email:     "sasa@foo-corp.com",
			ExpiresAt: "",
			Link:      "https://id.workos.test/passwordless/1234/confirm",
		}

	session, err := CreateSession(context.Background(), CreateSessionOpts{
		Email: "sasa@foo-corp.com",
		Type:  MagicLink,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, session)
}

func TestPasswordlessSendSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(sendSessionTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := SendSession(context.Background(), SendSessionOpts{
		SessionID: "session_id",
	})
	require.NoError(t, err)
}
