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
//
// On success, returns the AccessToken. On failure, returns an error which may be
// a GetAccessTokenError (NotInstalled or NeedsReauthorization) that can be checked
// with errors.Is or type assertion.
func GetAccessToken(
	ctx context.Context,
	opts GetAccessTokenOpts,
) (AccessToken, error) {
	return DefaultClient.GetAccessToken(ctx, opts)
}
