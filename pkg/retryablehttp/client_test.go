package retryablehttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type testServerResponse struct {
	http.Response
	Message string `json:"message"`
}

func TestDo(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := testServerResponse{
			Message: "Success",
		}

		responseBody, err := json.Marshal(response)
		require.NoError(t, err)
		_, err = w.Write(responseBody)
		require.NoError(t, err)
	}))
	defer testServer.Close()

	client := HttpClient{}
	req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)

	var resBody testServerResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&resBody)
	require.NoError(t, err)

	require.Equal(t, "Success", resBody.Message)
}

func TestDo_Retry(t *testing.T) {
	requests := 0

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch requests {
		case 0:
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte("Internal Server Error - retry request"))
			require.NoError(t, err)
		case 1:
			response := testServerResponse{
				Message: "Success",
			}

			responseBody, err := json.Marshal(response)
			require.NoError(t, err)
			_, err = w.Write(responseBody)
			require.NoError(t, err)
		default:
			require.Fail(t, "unexpected number of requests")
		}

		requests++
	}))
	defer testServer.Close()

	client := HttpClient{}
	req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)

	var resBody testServerResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&resBody)
	require.NoError(t, err)

	require.Equal(t, "Success", resBody.Message)
	require.Equal(t, 2, requests)
}

func TestShouldRetry(t *testing.T) {
	client := HttpClient{}

	t.Run("Max retry attempts reached", func(t *testing.T) {
		shouldRetry := client.shouldRetry(&http.Request{Method: http.MethodGet}, &http.Response{StatusCode: http.StatusInternalServerError}, nil, MaxRetryAttempts)
		require.False(t, shouldRetry)
	})

	t.Run("Request context error", func(t *testing.T) {
		ctxWithCancel, cancel := context.WithCancel(context.Background())
		cancel()
		req, err := http.NewRequestWithContext(ctxWithCancel, http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		shouldRetry := client.shouldRetry(req, &http.Response{StatusCode: http.StatusOK}, nil, 0)
		require.False(t, shouldRetry)
	})

	t.Run("Retry on request errors", func(t *testing.T) {
		shouldRetry := client.shouldRetry(&http.Request{Method: http.MethodGet}, nil, http.ErrHandlerTimeout, 0)
		require.True(t, shouldRetry)
	})

	t.Run("Retry on 50X response codes", func(t *testing.T) {
		shouldRetry := client.shouldRetry(&http.Request{Method: http.MethodGet}, &http.Response{StatusCode: http.StatusInternalServerError}, nil, 0)
		require.True(t, shouldRetry)

		shouldRetry = client.shouldRetry(&http.Request{Method: http.MethodGet}, &http.Response{StatusCode: http.StatusBadGateway}, nil, 0)
		require.True(t, shouldRetry)
	})
}
