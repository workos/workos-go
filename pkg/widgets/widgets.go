// Package `widgets` provides a client wrapping the WorkOS Widgets API.
package widgets

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Widgets functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Widgets API requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetToken generates an ephemeral widget token based on the provided options.
func GetToken(
	ctx context.Context,
	opts GetTokenOpts,
) (string, error) {
	return DefaultClient.GetToken(ctx, opts)
}
