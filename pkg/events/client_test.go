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
	tests := []struct {
		scenario string
		client   *Client
		options  ListEventsOpts
		expected ListEventsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Events",
			client: &Client{
				APIKey: "test",
			},
			options: ListEventsOpts{},
			expected: ListEventsResponse{
				Data: []Event{
					Event{
						ID:    "event_abcd1234",
						Event: "dsync.user.created",
						Data:  json.RawMessage(`{"foo":"bar"}`),
					},
				},
				ListMetadata: common.ListMetadata{
					After: "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getEventsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			events, err := client.ListEvents(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, events)
		})
	}
}

func getEventsTestHandler(w http.ResponseWriter, r *http.Request) {
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
