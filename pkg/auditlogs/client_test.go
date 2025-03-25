package auditlogs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/workos/workos-go/v4/pkg/common"
	"github.com/workos/workos-go/v4/pkg/workos_errors"

	"github.com/stretchr/testify/require"
)

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
				Errors:  []workos_errors.FieldError{{Field: "name", Code: "required_field"}},
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
		require.Equal(t, httpError.FieldErrors, []workos_errors.FieldError{{Field: "name", Code: "required_field"}})
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

func TestListActions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListActionsOpts
		expected ListActionsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Audit Log Actions",
			client: &Client{
				APIKey: "test",
			},
			options: ListActionsOpts{},
			expected: ListActionsResponse{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listActionsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			actions, err := client.ListActions(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, actions)
		})
	}
}

func listActionsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListActionsResponse
	}{
		ListActionsResponse: ListActionsResponse{
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
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

type defaultTestHandler struct {
	header *http.Header
}
