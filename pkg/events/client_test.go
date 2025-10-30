package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
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

		params := ListEventsOpts{
			Events: []string{"dsync.user.created"},
		}
		events, err := client.ListEvents(context.Background(), params)

		require.NoError(t, err)
		require.Equal(t, expectedResponse, events)
	})

	t.Run("ListEvents succeeds to fetch Events with a range_start and range_end", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(ListEventsTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		currentTime := time.Now()
		rangeStart := currentTime.AddDate(0, 0, -2)
		rangeEnd := currentTime.AddDate(0, 0, -1)

		params := ListEventsOpts{
			Events:     []string{"dsync.user.created"},
			RangeStart: rangeStart.String(),
			RangeEnd:   rangeEnd.String(),
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

		events, err := client.ListEvents(context.Background(), params)

		require.NoError(t, err)
		require.Equal(t, expectedResponse, events)
	})

	t.Run("ListEvents succeeds to fetch Events with an organization_id", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(ListEventsTestHandler))
		defer server.Close()
		client := &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
			APIKey:     "test",
		}

		params := ListEventsOpts{
			Events:         []string{"dsync.user.created"},
			OrganizationId: "org_1234",
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

		events, err := client.ListEvents(context.Background(), params)

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
