package auditlogs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
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

func TestAuditLogsListActions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listActionsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListActionsResponse{
		Data: []AuditLogAction{
			{
				Name: "document.updated",
				Schema: AuditLogActionSchema{
					Version: 1,
					Actor: AuditLogActionSchemaActor{
						ID:   "user_1",
						Name: "Test User",
						Type: "User",
					},
					Targets: []AuditLogActionSchemaTarget{
						{
							ID:   "document_39127",
							Name: "Test Document",
							Type: "document",
						},
					},
					Context: Context{
						Location:  "192.0.0.8",
						UserAgent: "Firefox",
					},
				},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}

	actionsResponse, err := ListActions(context.Background(), ListActionsOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, actionsResponse)
}
