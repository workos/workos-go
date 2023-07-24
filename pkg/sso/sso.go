// Package `sso` provides a client wrapping the WorkOS SSO API.
package sso

import (
	"context"
	"net/http"
	"net/url"
)

var (
	DefaultClient *Client
)

func Configure(apiKey, clientID string) {
	DefaultClient.APIKey = apiKey
	DefaultClient.ClientID = clientID
}

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func GetAuthorizationURL(opts GetAuthorizationURLOpts) (*url.URL, error) {
	return DefaultClient.GetAuthorizationURL(opts)
}

// GetProfileAndToken returns a profile describing the user that authenticated with
// WorkOS SSO.
func GetProfileAndToken(ctx context.Context, opts GetProfileAndTokenOpts) (ProfileAndToken, error) {
	return DefaultClient.GetProfileAndToken(ctx, opts)
}

// GetProfile returns a profile describing the user that authenticated with
// WorkOS SSO.
func GetProfile(ctx context.Context, opts GetProfileOpts) (Profile, error) {
	return DefaultClient.GetProfile(ctx, opts)
}

// Login returns a http.Handler that redirects client to the appropriate
// login provider.
func Login(opts GetAuthorizationURLOpts) http.Handler {
	return DefaultClient.GetLoginHandler(opts)
}

// GetConnection gets a Connection.
func GetConnection(
	ctx context.Context,
	opts GetConnectionOpts,
) (Connection, error) {
	return DefaultClient.GetConnection(ctx, opts)
}

// ListConnections gets a list of existing Connections.
func ListConnections(
	ctx context.Context,
	opts ListConnectionsOpts,
) (ListConnectionsResponse, error) {
	return DefaultClient.ListConnections(ctx, opts)
}

// DeleteConnection deletes a Connection.
func DeleteConnection(
	ctx context.Context,
	opts DeleteConnectionOpts,
) error {
	return DefaultClient.DeleteConnection(ctx, opts)
}
