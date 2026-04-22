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
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/google/uuid"
)

func isRetryableStatus(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
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
		ua := "workos-go/" + Version
		if c.appInfo.Name != "" {
			ua += " " + c.appInfo.Name + "/" + c.appInfo.Version
			if c.appInfo.URL != "" {
				ua += " (" + c.appInfo.URL + ")"
			}
		}
		req.Header.Set("User-Agent", ua)
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

		reqStart := time.Now()
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = &NetworkError{Err: err}
			if c.logger != nil {
				c.logger.Printf("workos: %s %s error=%v duration=%s", method, path, err, time.Since(reqStart))
			}
			continue
		}
		if c.logger != nil {
			c.logger.Printf("workos: %s %s status=%d duration=%s", method, path, resp.StatusCode, time.Since(reqStart))
		}

		if isRetryableStatus(resp.StatusCode) && attempt < maxRetries {
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

// buildURL composes a fully-qualified URL without making an HTTP request.
// Used by OAuth redirect endpoints (e.g. /sso/authorize, /user_management/sessions/logout)
// that need to hand a URL back to the caller for browser redirection.
// Honors WithRequestBaseURL from opts for parity with request().
func (c *Client) buildURL(path string, query url.Values, opts []RequestOption) string {
	cfg := &requestConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	baseURL := c.baseURL
	if cfg.baseURL != "" {
		baseURL = cfg.baseURL
	}
	u := strings.TrimRight(baseURL, "/") + path
	if encoded := query.Encode(); encoded != "" {
		u += "?" + encoded
	}
	return u
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
	jitter := time.Duration(rand.Int64N(int64(base)))
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
		RawBody:    string(body),
	}

	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			apiErr.RetryAfter = seconds
		}
	}

	_ = json.Unmarshal(body, apiErr)

	// Try to return a structured authentication error for known codes.
	if authErr := parseAuthenticationError(apiErr, body); authErr != nil {
		return authErr
	}

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

// parseAuthenticationError checks for known authentication error codes and
// returns a structured error type. Returns nil if the error is not a
// recognized authentication error.
func parseAuthenticationError(apiErr *APIError, body []byte) error {
	// Check code/message format (email_verification_required, mfa_*, organization_selection_required)
	if apiErr.Code != "" {
		switch apiErr.Code {
		case EmailVerificationRequiredCode:
			e := &EmailVerificationRequiredError{APIError: apiErr}
			_ = json.Unmarshal(body, e)
			return e
		case MFAEnrollmentCode:
			e := &MFAEnrollmentError{APIError: apiErr}
			_ = json.Unmarshal(body, e)
			if e.User.ID == "" {
				return nil // incomplete payload, fall back to generic
			}
			return e
		case MFAChallengeCode:
			e := &MFAChallengeError{APIError: apiErr}
			_ = json.Unmarshal(body, e)
			if e.User.ID == "" {
				return nil
			}
			return e
		case OrganizationSelectionRequiredCode:
			e := &OrganizationSelectionRequiredError{APIError: apiErr}
			_ = json.Unmarshal(body, e)
			if e.User.ID == "" {
				return nil
			}
			return e
		}
	}

	// Check error/error_description format (sso_required, organization_authentication_methods_required)
	if apiErr.ErrorCode != "" {
		switch apiErr.ErrorCode {
		case SSORequiredCode:
			e := &SSORequiredError{APIError: apiErr}
			_ = json.Unmarshal(body, e)
			return e
		case OrganizationAuthenticationMethodsRequiredCode:
			e := &OrganizationAuthenticationMethodsRequiredError{APIError: apiErr}
			_ = json.Unmarshal(body, e)
			return e
		}
	}

	return nil
}
