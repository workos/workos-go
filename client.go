// @oagen-ignore-file

package workos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/google/uuid"
)

var retryableStatuses = map[int]bool{
	429: true,
	500: true,
	502: true,
	503: true,
	504: true,
}

// request executes an HTTP request with retry logic.
func (c *Client) request(
	ctx context.Context,
	method string,
	path string,
	queryParams interface{},
	body interface{},
	result interface{},
	opts []RequestOption,
) (*http.Response, error) {
	cfg := &requestConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	baseURL := c.baseURL
	if cfg.baseURL != "" {
		baseURL = cfg.baseURL
	}

	maxRetries := c.maxRetries
	if cfg.maxRetries != nil {
		maxRetries = *cfg.maxRetries
	}

	idempotencyKey := cfg.idempotencyKey
	if method == http.MethodPost && idempotencyKey == "" {
		idempotencyKey = uuid.New().String()
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := backoff(attempt, lastErr)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		var bodyReader io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("workos: failed to marshal request body: %w", err)
			}
			bodyReader = bytes.NewReader(data)
		}

		requestURL := strings.TrimRight(baseURL, "/") + path
		if queryParams != nil {
			parsedURL, err := url.Parse(requestURL)
			if err != nil {
				return nil, fmt.Errorf("workos: failed to parse request URL: %w", err)
			}
			encodedQuery, err := encodeQuery(queryParams)
			if err != nil {
				return nil, err
			}
			queryValues := parsedURL.Query()
			for key, values := range encodedQuery {
				queryValues.Del(key)
				for _, value := range values {
					queryValues.Add(key, value)
				}
			}
			parsedURL.RawQuery = queryValues.Encode()
			requestURL = parsedURL.String()
		}
		req, err := http.NewRequestWithContext(ctx, method, requestURL, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("workos: failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "workos-go")
		if idempotencyKey != "" {
			req.Header.Set("Idempotency-Key", idempotencyKey)
		}
		if cfg.extraHeaders != nil {
			for k, vs := range cfg.extraHeaders {
				for _, v := range vs {
					req.Header.Add(k, v)
				}
			}
		}

		httpClient := c.httpClient
		if cfg.timeout > 0 {
			clonedClient := *httpClient
			clonedClient.Timeout = cfg.timeout
			httpClient = &clonedClient
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = &NetworkError{Err: err}
			continue
		}

		if retryableStatuses[resp.StatusCode] && attempt < maxRetries {
			lastErr = parseAPIError(resp)
			resp.Body.Close()
			continue
		}

		if resp.StatusCode >= 400 {
			defer resp.Body.Close()
			return resp, parseAPIError(resp)
		}

		if result != nil && resp.StatusCode != http.StatusNoContent {
			defer resp.Body.Close()
			if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
				return resp, fmt.Errorf("workos: failed to decode response: %w", err)
			}
		} else {
			resp.Body.Close()
		}

		return resp, nil
	}

	return nil, lastErr
}

func encodeQuery(params interface{}) (url.Values, error) {
	if params == nil {
		return nil, nil
	}
	if values, ok := params.(url.Values); ok {
		clone := url.Values{}
		for key, currentValues := range values {
			clone[key] = append([]string(nil), currentValues...)
		}
		return clone, nil
	}
	values, err := query.Values(params)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to encode query params: %w", err)
	}
	return values, nil
}

func backoff(attempt int, lastErr error) time.Duration {
	base := 500 * time.Millisecond
	max := 30 * time.Second

	// Check for Retry-After header
	var apiErr *APIError
	if errors.As(lastErr, &apiErr) && apiErr.RetryAfter > 0 {
		return time.Duration(apiErr.RetryAfter) * time.Second
	}

	wait := time.Duration(float64(base) * math.Pow(2, float64(attempt-1)))
	jitter := time.Duration(rand.Int63n(int64(base)))
	wait += jitter
	if wait > max {
		wait = max
	}
	return wait
}

func parseAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("X-Request-Id"),
	}

	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			apiErr.RetryAfter = seconds
		}
	}

	_ = json.Unmarshal(body, apiErr)

	switch resp.StatusCode {
	case 401:
		return &AuthenticationError{APIError: apiErr}
	case 404:
		return &NotFoundError{APIError: apiErr}
	case 422:
		return &UnprocessableEntityError{APIError: apiErr}
	case 429:
		return &RateLimitExceededError{APIError: apiErr}
	default:
		if resp.StatusCode >= 500 {
			return &ServerError{APIError: apiErr}
		}
		return apiErr
	}
}
