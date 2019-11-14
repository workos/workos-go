package auditlog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditLog(t *testing.T) {
	handler := &defaultTestHandler{}
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}

	server := httptest.NewServer(http.HandlerFunc(handlerFunc))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}

	SetAPIKey("test")

	err := Publish(context.TODO(), Event{})
	require.NoError(t, err)
}
