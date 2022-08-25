package auditlogs

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
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
		Metadata: map[string]interface{}{
			"successful": true,
		},
	},
	IdempotencyKey: "key",
}

func TestCreateEvent(t *testing.T) {
	t.Run("Idempotency Key is sent in the header", func(t *testing.T) {
		handler := defaultTestHandler{}
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			handler.header = &r.Header
			w.WriteHeader(http.StatusOK)
		}
		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:     server.Client(),
			EventsEndpoint: server.URL,
		}
		SetAPIKey("test")

		err := CreateEvent(context.TODO(), AuditLogEventOpts{
			IdempotencyKey: "the-idempotency-key",
		})
		require.Equal(t, handler.header.Get("Idempotency-Key"), "the-idempotency-key")
		require.NoError(t, err)
	})

	t.Run("401 requests returns an error", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "a-request-id")
			w.WriteHeader(http.StatusUnauthorized)
		}

		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:     server.Client(),
			EventsEndpoint: server.URL,
		}
		SetAPIKey("test")

		err := CreateEvent(context.TODO(), AuditLogEventOpts{})
		require.Equal(t, "a-request-id", err.(workos_errors.HTTPError).RequestID)
		require.Error(t, err)
	})

	t.Run("400 requests returns an error with description", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			type Error struct {
				Message string   `json:"message"`
				Code    string   `json:"code"`
				Errors  []string `json:"errors"`
			}

			errorResponse := Error{
				Message: "Audit Log could not be processed due to missing or incorrect data.",
				Code:    "invalid_audit_log",
				Errors:  []string{"error in a field"},
			}
			body, _ := json.Marshal(errorResponse)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(body)
		}

		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:     server.Client(),
			EventsEndpoint: server.URL,
		}
		SetAPIKey("test")

		err := CreateEvent(context.TODO(), AuditLogEventOpts{})
		require.Error(t, err)

		httpError := err.(workos_errors.HTTPError)
		require.Equal(t, httpError.Message, "Audit Log could not be processed due to missing or incorrect data.")
		require.Equal(t, httpError.Errors, []string{"error in a field"})
		require.Equal(t, httpError.ErrorCode, "invalid_audit_log")
	})
	t.Run("422 requests returns an error with description", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			type Error struct {
				Message string                     `json:"message"`
				Code    string                     `json:"code"`
				Errors  []workos_errors.FieldError `json:"errors"`
			}

			errorResponse := Error{
				Message: "Audit Log could not be processed due to missing or incorrect data.",
				Code:    "invalid_audit_log",
				Errors:  []workos_errors.FieldError{workos_errors.FieldError{Field: "name", Code: "required_field"}},
			}
			body, _ := json.Marshal(errorResponse)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write(body)
		}

		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:     server.Client(),
			EventsEndpoint: server.URL,
		}
		SetAPIKey("test")

		err := CreateEvent(context.TODO(), AuditLogEventOpts{})
		require.Error(t, err)

		httpError := err.(workos_errors.HTTPError)
		require.Equal(t, httpError.Message, "Audit Log could not be processed due to missing or incorrect data.")
		require.Equal(t, httpError.FieldErrors, []workos_errors.FieldError{workos_errors.FieldError{Field: "name", Code: "required_field"}})
		require.Equal(t, httpError.ErrorCode, "invalid_audit_log")
	})
}

func TestCreateExports(t *testing.T) {
	t.Run("Call succeeds", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			body, _ := json.Marshal(CreateExportResponse{
				Id: "test",
			})
			w.WriteHeader(http.StatusCreated)
			w.Write(body)
		}
		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:      server.Client(),
			ExportsEndpoint: server.URL,
		}
		SetAPIKey("test")

		body, err := CreateExport(context.TODO(), CreateExportOpts{})
		require.Equal(t, body, CreateExportResponse{
			Id: "test",
		})
		require.NoError(t, err)
	})
	t.Run("Call succeed with filters", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			var opts CreateExportOpts
			dec := json.NewDecoder(r.Body)
			dec.Decode(&opts)

			require.Equal(t, opts.Actions[0], "create-user")
			require.Equal(t, opts.Targets[0], "user")
			require.Equal(t, opts.Actors, []string{"Jon", "Smith"})

			body, _ := json.Marshal(CreateExportResponse{
				Id: "test123",
			})

			w.Write(body)
			w.WriteHeader(http.StatusOK)
		}
		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:      server.Client(),
			ExportsEndpoint: server.URL,
		}
		SetAPIKey("test")

		body, err := CreateExport(context.TODO(), CreateExportOpts{
			Actions: []string{"create-user"},
			Targets: []string{"user"},
			Actors:  []string{"Jon", "Smith"},
		})
		require.Equal(t, body, CreateExportResponse{
			Id: "test123",
		})
		require.NoError(t, err)
	})
	t.Run("401 requests returns an error", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}
		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:      server.Client(),
			ExportsEndpoint: server.URL,
		}
		SetAPIKey("test")

		_, err := CreateExport(context.TODO(), CreateExportOpts{})
		require.Error(t, err)
	})
}

func TestGetExports(t *testing.T) {
	t.Run("Call succeeds", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			body, _ := json.Marshal(GetExportResponse{
				Id: "test",
			})
			w.WriteHeader(http.StatusCreated)
			w.Write(body)
		}
		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:      server.Client(),
			ExportsEndpoint: server.URL,
		}
		SetAPIKey("test")

		body, err := GetExport(context.TODO(), GetExportOpts{})
		require.Equal(t, body, GetExportResponse{
			Id: "test",
		})
		require.NoError(t, err)
	})
	t.Run("401 requests returns an error", func(t *testing.T) {
		handlerFunc := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}
		server := httptest.NewServer(http.HandlerFunc(handlerFunc))
		defer server.Close()

		DefaultClient = &Client{
			HTTPClient:      server.Client(),
			ExportsEndpoint: server.URL,
		}
		SetAPIKey("test")

		_, err := GetExport(context.TODO(), GetExportOpts{})
		require.Error(t, err)
	})
}

type defaultTestHandler struct {
	header *http.Header
}

// Unit test to hit the prod api directly. Uncomment and provide an APIKey to
// test.

func TestClientCreateEventLive(t *testing.T) {
	client := &Client{
		APIKey:         "sk_test_a2V5XzAxRzNZSzc1OFowVENXTlQ5QzlEV1ROUUswLGhNYjcyckRpV2tZS3VFbWFXV1VPSU9vT1E",
		EventsEndpoint: "https://api.workos-test.com/audit_logs/events",
	}
	client.init()

	err := client.CreateEvent(context.TODO(), AuditLogEventOpts{
		Organization: "org_01G7SXG5PT45NP3E9Z38G22GPY",
		Event: Event{
			Action: "team.created",
			Actor: Actor{
				Id:   "o5fdfsdfUMCAuunNN3Iwfs34gMw",
				Name: "jonatas",
				Type: "user",
				Metadata: map[string]interface{}{
					"Email": "person@workos.com",
				},
			},
			Context: Context{
				Location: "79.226.116.209",
			},
			Targets: []Target{
				Target{Id: "team_123", Type: "team"},
			},
		},
		IdempotencyKey: uuid.New().String(),
	})

	require.NoError(t, err)
}
