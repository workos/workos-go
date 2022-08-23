package auditlogs

import (
	"context"
	"github.com/workos/workos-go/pkg/workos_errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var event = AuditLogEventOpts{
	Organization: "org_123456",
	Event: Event{
		Action:     "document.updated",
		OccurredAt: time.Now(),
		Actor: Actor{
			Id:   "user_1",
			Name: "Jon Smith",
			Type: "User",
		},
		Targets: []Target{
			{
				Id:   "document_39127",
				Type: "document",
			},
		},
		Context: Context{
			Location:  "192.0.0.8",
			UserAgent: "Firefox",
		},
		Metadata: Metadata{
			"successful": true,
		},
	},
	IdempotencyKey: "key",
}

func TestCreateEvent(t *testing.T) {
	handler := &defaultTestHandler{}

	t.Run("Idempotency Key is sent in the header", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			handler.header = &r.Header
			w.WriteHeader(http.StatusOK)
		}
		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := CreateEvent(context.TODO(), AuditLogEventOpts{
			IdempotencyKey: "the-idempotency-key",
		})
		require.Equal(t, handler.header.Get("Idempotency-Key"), "the-idempotency-key")
		require.NoError(t, err)
	})

	t.Run("401 requests returns an error ", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "a-request-id")
			w.WriteHeader(http.StatusUnauthorized)
		}

		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := CreateEvent(context.TODO(), AuditLogEventOpts{})
		require.Equal(t, "a-request-id", err.(workos_errors.HTTPError).RequestID)
		require.Error(t, err)
	})

	t.Run("400 requests returns an error with description", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "a-request-id")
			w.WriteHeader(http.StatusBadRequest)
		}

		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient: server.Client(),
			Endpoint:   server.URL,
		}
		SetAPIKey("test")

		err := CreateEvent(context.TODO(), AuditLogEventOpts{})
		require.Equal(t, "a-request-id", err.(workos_errors.HTTPError).RequestID)
		require.Error(t, err)
	})
}

type defaultTestHandler struct {
	header *http.Header
}
