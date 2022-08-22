package audittrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/workos/workos-go/pkg/common"
)

func TestClientPublish(t *testing.T) {
	tests := []struct {
		scenario string
		event    EventOpts
		err      bool
	}{
		{
			scenario: "event with invalid metadata returns an error",
			event: EventOpts{
				Metadata: map[string]interface{}{
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "",
				},
			},
			err: true,
		},
		{
			scenario: "encoding to json is returning an error",
			event: EventOpts{
				Metadata: map[string]interface{}{
					"func": func() {},
				},
				IdempotencyKey: "test",
			},
			err: true,
		},
		{
			scenario: "server is returning an 400",
			event: EventOpts{
				Metadata: map[string]interface{}{
					"err": "simulated 400",
				},
				IdempotencyKey: "test",
			},
			err: true,
		},
		{
			scenario: "event is published",
			event: EventOpts{
				Action:         "gosdk.publish",
				ActionType:     "c",
				IdempotencyKey: "test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(&defaultTestHandler{})
			defer server.Close()

			client := Client{}
			client.init()
			client.Endpoint = server.URL
			client.APIKey = "test"
			client.HTTPClient = server.Client()

			err := client.Publish(context.TODO(), test.event)
			if test.err {
				require.Error(t, err)
				t.Log(err)
				return
			}
			require.NoError(t, err)
		})
	}
}

type defaultTestHandler struct {
	requests int
	errors   int
}

func (h *defaultTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.requests++

	var event EventOpts

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&event); err != nil {
		h.errors++
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	requiredHeaders := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer test",
	}

	for k, v := range requiredHeaders {
		val := r.Header.Get(k)

		if val != v {
			h.errors++
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad header value for " + k))
			return
		}
	}

	if errMsg, ok := event.Metadata["err"]; ok {
		h.errors++
		w.WriteHeader(http.StatusBadRequest)

		if msg, ok := errMsg.(string); ok {
			w.Write([]byte(msg))
		}

		return
	}

	w.WriteHeader(http.StatusOK)
}

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
			scenario: "Request returns Audit Trail Events",
			client: &Client{
				APIKey: "test",
			},
			options: ListEventsOpts{},
			expected: ListEventsResponse{
				Data: []Event{
					Event{
						ID:         "event_0",
						Group:      "foo-corp.com",
						Latitude:   "",
						Longitude:  "",
						Location:   "::1",
						Type:       "r",
						ActorName:  "demo@foo-corp.com",
						ActorID:    "user_0",
						TargetName: "http_request",
						TargetID:   "",
						Metadata:   Metadata{},
						OccurredAt: "",
						Action: EventAction{
							ID:   "evt_action_0",
							Name: "user.searched_directories",
						},
					},
				},
				ListMetadata: common.ListMetadata{
					Before: "",
					After:  "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listEventsTestHandler))
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

func listEventsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "Authentication error", http.StatusUnauthorized)
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
				Event{
					ID:         "event_0",
					Group:      "foo-corp.com",
					Latitude:   "",
					Longitude:  "",
					Location:   "::1",
					Type:       "r",
					ActorName:  "demo@foo-corp.com",
					ActorID:    "user_0",
					TargetName: "http_request",
					TargetID:   "",
					Metadata:   Metadata{},
					OccurredAt: "",
					Action: EventAction{
						ID:   "evt_action_0",
						Name: "user.searched_directories",
					},
				},
			},
			ListMetadata: common.ListMetadata{
				Before: "",
				After:  "",
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

// Unit test to hit the prod api directly. Uncomment and provide an APIKey to
// test.
//
// func TestClientPublishLive(t *testing.T) {
// 	client := &Client{
// 		APIKey: "xxxxxx",
// 	}
// 	client.init()

// 	err := client.Publish(context.TODO(), EventOpts{
// 		Action:         "gosdk.publish",
// 		ActionType:     Create,
// 		ActorName:      "Jonhy Maxoo",
// 		Group:          "workos.com",
// 		Location:       "55.27.223.42",
// 		OccurredAt:     time.Now(),
// 		IdempotencyKey: uuid.New().String(),
// 	})

// 	require.NoError(t, err)
// }
