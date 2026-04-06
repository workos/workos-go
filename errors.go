package workos

import "fmt"

// APIError represents an error returned by the WorkOS API.
type APIError struct {
	StatusCode int    `json:"-"`
	RequestID  string `json:"-"`
	RetryAfter int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("workos: %d %s: %s (request_id: %s)", e.StatusCode, e.Code, e.Message, e.RequestID)
}

// AuthenticationError represents 401 authentication errors.
type AuthenticationError struct {
	*APIError
}

func (e *AuthenticationError) Error() string { return e.APIError.Error() }
func (e *AuthenticationError) Unwrap() error { return e.APIError }

// NotFoundError represents 404 not found errors.
type NotFoundError struct {
	*APIError
}

func (e *NotFoundError) Error() string { return e.APIError.Error() }
func (e *NotFoundError) Unwrap() error { return e.APIError }

// UnprocessableEntityError represents 422 validation errors.
type UnprocessableEntityError struct {
	*APIError
}

func (e *UnprocessableEntityError) Error() string { return e.APIError.Error() }
func (e *UnprocessableEntityError) Unwrap() error { return e.APIError }

// RateLimitExceededError represents 429 rate limit errors.
type RateLimitExceededError struct {
	*APIError
}

func (e *RateLimitExceededError) Error() string { return e.APIError.Error() }
func (e *RateLimitExceededError) Unwrap() error { return e.APIError }

// ServerError represents 5xx server errors.
type ServerError struct {
	*APIError
}

func (e *ServerError) Error() string { return e.APIError.Error() }
func (e *ServerError) Unwrap() error { return e.APIError }

// NetworkError represents a connection failure.
type NetworkError struct {
	Err error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("workos: network error: %v", e.Err)
}

func (e *NetworkError) Unwrap() error { return e.Err }
