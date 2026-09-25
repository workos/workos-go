// @oagen-ignore-file

package workos_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	workos "github.com/workos/workos-go/v10"
)

func TestManualDirectorySyncAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/directories/directory_123/sync", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Empty(t, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"status":"queued"}`)
	}))
	defer server.Close()
	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))

	result, err := client.DirectorySync().Sync(context.Background(), "directory_123")

	require.NoError(t, err)
	require.Equal(t, "queued", result.Status)
}

func TestManualDirectorySyncRejections(t *testing.T) {
	for _, outcome := range []struct {
		status int
		code   string
	}{
		{409, "directory_sync_in_progress"},
		{422, "directory_sync_unsupported"},
		{429, "directory_sync_rate_limited"},
		{503, "directory_sync_disabled"},
	} {
		t.Run(outcome.code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(outcome.status)
				fmt.Fprintf(w, `{"code":%q,"message":"Not queued.","retry_after_seconds":120}`, outcome.code)
			}))
			defer server.Close()
			client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL), workos.WithMaxRetries(0))

			result, err := client.DirectorySync().Sync(context.Background(), "directory_123")

			require.Nil(t, result)
			var apiError *workos.APIError
			require.ErrorAs(t, err, &apiError)
			require.Equal(t, outcome.status, apiError.StatusCode)
			require.Equal(t, outcome.code, apiError.Code)
			if outcome.status == 429 {
				require.Equal(t, 120, apiError.RetryAfter)
			}
		})
	}
}
