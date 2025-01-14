// Package `roles` provides a client wrapping the WorkOS Roles API.
package roles

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Roles functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Roles API requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// ListRoles lists all Roles in an environment.
func ListRoles(
	ctx context.Context,
	opts ListRolesOpts,
) (ListRolesResponse, error) {
	return DefaultClient.ListRoles(ctx, opts)
}
