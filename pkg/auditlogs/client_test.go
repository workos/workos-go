package auditlogs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
	"github.com/workos/workos-go/v6/pkg/workos_errors"
)

var event = CreateEventOpts{
	OrganizationID: "org_123456",
	Event: Event{
		Action:     "document.updated",
		OccurredAt: time.Now(),
		Actor: Actor{
			ID:   "user_1",
			Name: "Jon Smith",
			Type: "User",
		},
		Targets: []Target{
			{
				ID:   "document_39127",
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

		err := CreateEvent(context.TODO(), CreateEventOpts{
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

		err := CreateEvent(context.TODO(), CreateEventOpts{})
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

		err := CreateEvent(context.TODO(), CreateEventOpts{})
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

		err := CreateEvent(context.TODO(), CreateEventOpts{})
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
			body, _ := json.Marshal(AuditLogExport{
				ID: "test",
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
		require.Equal(t, body, AuditLogExport{
			ID: "test",
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
			require.Equal(t, opts.ActorNames, []string{"Jon", "Smith"})
			require.Equal(t, opts.ActorIds, []string{"user:1234"})

			body, _ := json.Marshal(AuditLogExport{
				ID: "test123",
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
			Actions:    []string{"create-user"},
			Targets:    []string{"user"},
			Actors:     []string{"Jon", "Smith"},
			ActorNames: []string{"Jon", "Smith"},
			ActorIds:   []string{"user:1234"},
		})
		require.Equal(t, body, AuditLogExport{
			ID: "test123",
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
			body, _ := json.Marshal(AuditLogExport{
				ID: "test",
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
		require.Equal(t, body, AuditLogExport{
			ID: "test",
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

func TestCreateEvent_AutoGeneratesIdempotencyKey(t *testing.T) {
	// Test that when IdempotencyKey is empty, SDK auto-generates one

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")

		// Assert idempotency key was sent
		require.NotEmpty(t, idempotencyKey, "Expected Idempotency-Key header to be present")

		// Assert it's a valid UUID format (basic check - UUID v4 is 36 chars with hyphens)
		require.Equal(t, 36, len(idempotencyKey), "Expected UUID format (36 characters)")

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{
		APIKey:         "test_key",
		EventsEndpoint: server.URL,
		HTTPClient:     server.Client(),
	}

	err := client.CreateEvent(context.Background(), CreateEventOpts{
		OrganizationID: "org_123",
		Event: Event{
			Action: "test.action",
			Actor:  Actor{ID: "user_123", Type: "user", Name: "Test User"},
			Targets: []Target{
				{ID: "target_123", Type: "test", Name: "Test Target"},
			},
			Context: Context{
				Location:  "127.0.0.1",
				UserAgent: "test",
			},
		},
		// Note: NOT providing IdempotencyKey
	})

	require.NoError(t, err)
}

func TestCreateEvent_UsesProvidedIdempotencyKey(t *testing.T) {
	// Test that when user provides IdempotencyKey, SDK uses it

	expectedKey := "user-provided-key-12345"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idempotencyKey := r.Header.Get("Idempotency-Key")

		require.Equal(t, expectedKey, idempotencyKey, "Expected provided idempotency key to be used")

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{
		APIKey:         "test_key",
		EventsEndpoint: server.URL,
		HTTPClient:     server.Client(),
	}

	err := client.CreateEvent(context.Background(), CreateEventOpts{
		OrganizationID: "org_123",
		Event: Event{
			Action: "test.action",
			Actor:  Actor{ID: "user_123", Type: "user", Name: "Test User"},
			Targets: []Target{
				{ID: "target_123", Type: "test", Name: "Test Target"},
			},
			Context: Context{
				Location:  "127.0.0.1",
				UserAgent: "test",
			},
		},
		IdempotencyKey: expectedKey, // User provides their own key
	})

	require.NoError(t, err)
}

func TestCreateEvent_RetriesOn5xxErrors(t *testing.T) {
	// Test that SDK retries on 5xx errors

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// First 2 attempts fail with 500
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message": "Internal server error"}`))
		} else {
			// Third attempt succeeds
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := &Client{
		APIKey:         "test_key",
		EventsEndpoint: server.URL,
		HTTPClient: &retryablehttp.HttpClient{
			Client: http.Client{Timeout: 10 * time.Second},
		},
	}

	err := client.CreateEvent(context.Background(), CreateEventOpts{
		OrganizationID: "org_123",
		Event: Event{
			Action: "test.action",
			Actor:  Actor{ID: "user_123", Type: "user", Name: "Test User"},
			Targets: []Target{
				{ID: "target_123", Type: "test", Name: "Test Target"},
			},
			Context: Context{
				Location:  "127.0.0.1",
				UserAgent: "test",
			},
		},
	})

	require.NoError(t, err, "CreateEvent should succeed after retries")
	require.Equal(t, 3, attempts, "Expected 3 attempts")
}

func TestCreateEvent_DoesNotRetryOn4xxErrors(t *testing.T) {
	// Test that SDK does NOT retry on 4xx client errors

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message": "Bad request"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:         "test_key",
		EventsEndpoint: server.URL,
		HTTPClient: &retryablehttp.HttpClient{
			Client: http.Client{Timeout: 10 * time.Second},
		},
	}

	err := client.CreateEvent(context.Background(), CreateEventOpts{
		OrganizationID: "org_123",
		Event: Event{
			Action: "test.action",
			Actor:  Actor{ID: "user_123", Type: "user", Name: "Test User"},
			Targets: []Target{
				{ID: "target_123", Type: "test", Name: "Test Target"},
			},
			Context: Context{
				Location:  "127.0.0.1",
				UserAgent: "test",
			},
		},
	})

	require.Error(t, err, "Expected error for 400 response")
	require.Equal(t, 1, attempts, "Expected only 1 attempt (no retries on 4xx)")
}

func TestCreateEvent_RetriesOn429Errors(t *testing.T) {
	// Test that SDK retries on 429 rate limit errors

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			// First attempt fails with 429
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1") // Wait 1 second
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message": "Too many requests"}`))
		} else {
			// Second attempt succeeds
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := &Client{
		APIKey:         "test_key",
		EventsEndpoint: server.URL,
		HTTPClient: &retryablehttp.HttpClient{
			Client: http.Client{Timeout: 10 * time.Second},
		},
	}

	err := client.CreateEvent(context.Background(), CreateEventOpts{
		OrganizationID: "org_123",
		Event: Event{
			Action: "test.action",
			Actor:  Actor{ID: "user_123", Type: "user", Name: "Test User"},
			Targets: []Target{
				{ID: "target_123", Type: "test", Name: "Test Target"},
			},
			Context: Context{
				Location:  "127.0.0.1",
				UserAgent: "test",
			},
		},
	})

	require.NoError(t, err, "CreateEvent should succeed after retrying on 429")
	require.Equal(t, 2, attempts, "Expected 2 attempts")
}
