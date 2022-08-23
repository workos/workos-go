package auditlogs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditLogsCreateEvent(t *testing.T) {
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	server := httptest.NewServer(http.HandlerFunc(handlerFunc))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}

	SetAPIKey("test")

	err := CreateEvent(context.TODO(), AuditLogEventOpts{})
	require.NoError(t, err)
}
