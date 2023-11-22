package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v3/pkg/common"
)

func TestEventsListEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(ListEventsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListEventsResponse{
		Data: []Event{
			{
				ID:    "event_abcd1234",
				Event: "dsync.user.created",
				Data:  json.RawMessage(`{"foo":"bar"}`),
			},
		},
		ListMetadata: common.ListMetadata{
			After: "",
		},
	}
	eventsResponse, err := ListEvents(context.Background(), ListEventsOpts{})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, eventsResponse)
}
