package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v2/pkg/common"
)

func TestListEvents(t *testing.T) {
	t.Run("ListEvents succeeds to fetch Events", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(ListEventsTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

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

		events, err := client.ListEvents(context.Background(), ListEventsOpts{})

		require.NoError(t, err)
		require.Equal(t, expectedResponse, events)
	})
}

func ListEventsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(struct {
		ListEventsResponse
	}{
		ListEventsResponse: ListEventsResponse{
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
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
