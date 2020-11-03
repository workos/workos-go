// Package `passwordless` provides a client wrapping the WorkOS Magic Link API.
package passwordless

import (
	"context"
)

// DefaultClient is the client used by the SetAPIKey, CreateSession, and SendSession functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Passwordless requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// CreateSession creates a new Passwordless Session
func CreateSession(
	ctx context.Context,
	opts CreateSessionOpts,
) (PasswordlessSession, error) {
	return DefaultClient.CreateSession(ctx, opts)
}

// SendSession sends a Passwordless Session via email
func SendSession(
	ctx context.Context,
	opts SendSessionOpts,
) error {
	return DefaultClient.SendSession(ctx, opts)
}
