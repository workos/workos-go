package alog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublisherPublish(t *testing.T) {
	tests := []struct {
		scenario string
		event    Event
		err      bool
	}{
		{
			scenario: "encoding to json is returning an error",
			event: Event{
				Metadata: map[string]interface{}{
					"func": func() {},
				},
				indempotencyKey: "test",
			},
			err: true,
		},
		{
			scenario: "server is returning an 400",
			event: Event{
				Metadata: map[string]interface{}{
					"err": "simulated 400",
				},
				indempotencyKey: "test",
			},
			err: true,
		},
		{
			scenario: "event is published",
			event: Event{
				indempotencyKey: "test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(&defaultTestHandler{})
			defer server.Close()

			pub := Publisher{}
			pub.init()
			pub.Endpoint = server.URL
			pub.APIKey = "test"
			pub.Client = server.Client()
			pub.Log = t.Logf
			defer pub.Close()

			err := pub.publish(context.TODO(), test.event)
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

	var event Event

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&event); err != nil {
		h.errors++
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	requiredHeaders := map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": "test",
		"Authorization":   "Bearer test",
	}

	for k, v := range requiredHeaders {
		val := r.Header.Get(k)

		switch k {
		case "Idempotency-Key":
			if val == "" {
				h.errors++
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("no indempotency key found"))
				return
			}

		default:
			if val != v {
				h.errors++
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("bad header value for " + k))
				return
			}
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

// Unit test to hit the prod api directly. Uncomment and provide an APIKey to
// test.
//
// func TestPublisherPublishLive(t *testing.T) {
// 	pub := &Publisher{
// 		APIKey: "xxxxxx",
// 	}
// 	pub.init()

// 	err := pub.publish(context.TODO(), Event{
// 		Action:     "gosdk.publish",
// 		ActionType: "w",
// 		ActorName:  "Maxence Charriere",
// 		Group:      "workos.com",
// 		// Location:        "55.27.223.42",
// 		OccurredAt:      time.Now(),
// 		indempotencyKey: uuid.New().String(),
// 	})

// 	require.NoError(t, err)
// }