// Package `permissions` provides a client wrapping the WorkOS Permissions API.
package permissions

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Permissions functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Permissions API requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// ListPermissions lists all Permissions in an environment.
func ListPermissions(
	ctx context.Context,
	opts ListPermissionsOpts,
) (ListPermissionsResponse, error) {
	return DefaultClient.ListPermissions(ctx, opts)
}
