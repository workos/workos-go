package auditlogs

import (
	"context"
	"encoding/json"
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
		HTTPClient:     server.Client(),
		EventsEndpoint: server.URL,
	}

	SetAPIKey("test")

	err := CreateEvent(context.TODO(), CreateEventOpts{})
	require.NoError(t, err)
}

func TestAuditLogsCreateExport(t *testing.T) {
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		body := AuditLogExport{}
		payload, _ := json.Marshal(body)
		w.Write(payload)
		w.WriteHeader(http.StatusOK)
	}

	server := httptest.NewServer(http.HandlerFunc(handlerFunc))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient:      server.Client(),
		ExportsEndpoint: server.URL,
	}

	SetAPIKey("test")

	_, err := CreateExport(context.TODO(), CreateExportOpts{})
	require.NoError(t, err)
}

func TestAuditLogsGetExport(t *testing.T) {
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		body := AuditLogExport{}
		payload, _ := json.Marshal(body)
		w.Write(payload)
		w.WriteHeader(http.StatusOK)
	}

	server := httptest.NewServer(http.HandlerFunc(handlerFunc))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient:      server.Client(),
		ExportsEndpoint: server.URL,
	}

	SetAPIKey("test")

	_, err := GetExport(context.TODO(), GetExportOpts{})
	require.NoError(t, err)
}
