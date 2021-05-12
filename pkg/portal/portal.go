// Package `portal` provides a client wrapping the WorkOS Admin Portal API.
package portal

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Admin Portal functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Admin Portal requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GenerateLink generates an ephemeral link to the Admin Portal
func GenerateLink(
	ctx context.Context,
	opts GenerateLinkOpts,
) (string, error) {
	return DefaultClient.GenerateLink(ctx, opts)
}
