// Package users provides a client wrapping the WorkOS User Management API.
package users

import (
	"context"
	"net/http"
)

var (
	// DefaultClient is the client used by User management methods
	DefaultClient = NewClient("")
)

// Client represents a client that fetch SSO data from WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	//
	// REQUIRED.
	APIKey string

	// The http.Client that is used to send request to WorkOS.
	//
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API.
	//
	// Defaults to https://api.workos.com.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)
}

// SetAPIKey configures the default client that is used by the User management methods
// It must be called before using those functions.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetUser gets a User.
func GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (User, error) {
	return DefaultClient.GetUser(ctx, opts)
}

// ListUsers gets a list of Users.
func ListUsers(
	ctx context.Context,
	opts ListUsersOpts,
) (ListUsersResponse, error) {
	return DefaultClient.ListUsers(ctx, opts)
}

// CreateUser creates a User.
func CreateUser(
	ctx context.Context,
	opts CreateUserOpts,
) (User, error) {
	return DefaultClient.CreateUser(ctx, opts)
}

func AuthenticateUserWithPassword(
	ctx context.Context,
	opts AuthenticateUserWithPasswordOpts,
) (AuthenticationResponse, error) {
	return DefaultClient.AuthenticateUserWithPassword(ctx, opts)
}

func AuthenticateUserWithToken(
	ctx context.Context,
	opts AuthenticateUserWithTokenOpts,
) (AuthenticationResponse, error) {
	return DefaultClient.AuthenticateUserWithToken(ctx, opts)
}
