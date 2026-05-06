// @oagen-ignore-file

package workos_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v8"
)

func TestClient_UserAgentIncludesVersion(t *testing.T) {
	var capturedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"org_01","name":"Test Org"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	_, err := client.Organizations().Get(context.Background(), "org_01")
	require.NoError(t, err)
	require.Equal(t, "workos-go/"+workos.Version, capturedUserAgent)
}

func TestClient_Retry429ThenSuccess(t *testing.T) {
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempt.Add(1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"code":"rate_limit_exceeded","message":"Too Many Requests"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"org_01","name":"Test Org"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.Organizations().Get(context.Background(), "org_01")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, int32(2), attempt.Load(), "expected retry after 429")
}

func TestClient_RetryAfterHeader(t *testing.T) {
	start := time.Now()
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempt.Add(1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"code":"rate_limit_exceeded","message":"Too Many Requests"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"org_01","name":"Test Org"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.Organizations().Get(context.Background(), "org_01")
	require.NoError(t, err)
	require.NotNil(t, result)
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 900*time.Millisecond, "should have waited ~1s for Retry-After")
}

func TestClient_MaxRetryExhaustion(t *testing.T) {
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"code":"rate_limit_exceeded","message":"Too Many Requests"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	_, err := client.Organizations().Get(context.Background(), "org_01")
	require.Error(t, err)
	require.IsType(t, &workos.RateLimitExceededError{}, err)
	// Default max retries is 3 (initial + 3 retries = 4 attempts)
	require.GreaterOrEqual(t, attempt.Load(), int32(2), "should have retried at least once")
}

func TestClient_NonRetryableStatusNotRetried(t *testing.T) {
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code":"bad_request","message":"Bad Request"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	_, err := client.Organizations().Get(context.Background(), "org_01")
	require.Error(t, err)
	require.Equal(t, int32(1), attempt.Load(), "non-retryable 400 should not be retried")
}

func TestClient_IdempotencyKeyOnPOST(t *testing.T) {
	var capturedKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"org_01","name":"Test Org"}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	_, err := client.Organizations().Create(context.Background(), &workos.OrganizationsCreateParams{
		Name: "Test Org",
	})
	require.NoError(t, err)
	require.NotEmpty(t, capturedKey, "POST requests should include an Idempotency-Key header")
	// Verify it looks like a UUID (36 chars with hyphens)
	require.Len(t, capturedKey, 36)
}
