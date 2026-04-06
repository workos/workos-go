// @oagen-ignore-file

// Package workos provides a Go client for the WorkOS API.
package workos

import (
	"net/http"
	"time"
)

const (
	defaultBaseURL    = "https://api.workos.com"
	defaultTimeout    = 60 * time.Second
	defaultMaxRetries = 3
)

// ClientOption configures the Client.
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = client }
}

// WithMaxRetries sets the maximum number of retries.
func WithMaxRetries(n int) ClientOption {
	return func(c *Client) { c.maxRetries = n }
}

// WithClientID sets the client ID (used for authentication flows).
func WithClientID(id string) ClientOption {
	return func(c *Client) { c.clientID = id }
}

// RequestOption configures a single API request.
type RequestOption func(*requestConfig)

type requestConfig struct {
	extraHeaders   http.Header
	timeout        time.Duration
	maxRetries     *int
	baseURL        string
	idempotencyKey string
}

// WithExtraHeaders adds extra headers to the request.
func WithExtraHeaders(h http.Header) RequestOption {
	return func(r *requestConfig) { r.extraHeaders = h }
}

// WithTimeout sets a timeout for the request.
func WithTimeout(d time.Duration) RequestOption {
	return func(r *requestConfig) { r.timeout = d }
}

// WithIdempotencyKey sets an idempotency key for the request.
func WithIdempotencyKey(key string) RequestOption {
	return func(r *requestConfig) { r.idempotencyKey = key }
}

// WithRequestMaxRetries overrides the max retries for a single request.
func WithRequestMaxRetries(n int) RequestOption {
	return func(r *requestConfig) { r.maxRetries = &n }
}

// WithRequestBaseURL overrides the base URL for a single request.
func WithRequestBaseURL(url string) RequestOption {
	return func(r *requestConfig) { r.baseURL = url }
}
