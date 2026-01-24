// Package `pipes` provides a client wrapping the WorkOS Pipes API.
package pipes

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Pipes functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Pipes requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetAccessToken retrieves an OAuth access token for a third-party data provider
// on behalf of a user.
func GetAccessToken(
	ctx context.Context,
	opts GetAccessTokenOpts,
) (GetAccessTokenResponse, error) {
	return DefaultClient.GetAccessToken(ctx, opts)
}
