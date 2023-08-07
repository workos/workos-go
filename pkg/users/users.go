// Package users provides a client wrapping the WorkOS User Management API.
package users

import "context"

var (
	// DefaultClient is the client used by GetAuthorizationURL, GetProfileAndToken and
	// Login functions.
	DefaultClient = &Client{}
)

// Configure configures the default client that is used by the User management methods
// It must be called before using those functions.
func Configure(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetUser gets a User.
func GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (User, error) {
	return DefaultClient.GetUser(ctx, opts)
}
