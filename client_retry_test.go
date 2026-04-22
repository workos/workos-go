// @oagen-ignore-file

package workos

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetry_500ThenSuccess(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"code":"server_error","message":"Internal Server Error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"org_123","name":"Test"}`))
	}))
	defer server.Close()

	client := NewClient("sk_test", WithBaseURL(server.URL), WithMaxRetries(2))
	result, err := client.Organizations().Get(context.Background(), "org_123")
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if result.ID != "org_123" {
		t.Fatalf("expected org_123, got: %s", result.ID)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got: %d", attempts.Load())
	}
}

func TestRetry_RetryAfterHeaderRespected(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"code":"rate_limit","message":"Rate limited"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"org_123","name":"Test"}`))
	}))
	defer server.Close()

	client := NewClient("sk_test", WithBaseURL(server.URL), WithMaxRetries(1))
	start := time.Now()
	_, err := client.Organizations().Get(context.Background(), "org_123")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	// Retry-After: 1 should cause at least ~1s delay
	if elapsed < 900*time.Millisecond {
		t.Fatalf("expected retry delay of ~1s, got: %s", elapsed)
	}
}

func TestRetry_ContextCanceledDuringBackoff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code":"server_error","message":"fail"}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	client := NewClient("sk_test", WithBaseURL(server.URL), WithMaxRetries(5))
	_, err := client.Organizations().Get(ctx, "org_123")
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
}

func TestRetry_MaxRetriesZeroDisablesRetry(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code":"server_error","message":"fail"}`))
	}))
	defer server.Close()

	client := NewClient("sk_test", WithBaseURL(server.URL), WithMaxRetries(0))
	_, err := client.Organizations().Get(context.Background(), "org_123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts.Load() != 1 {
		t.Fatalf("expected 1 attempt (no retries), got: %d", attempts.Load())
	}
}
