// Package `sso` provides a client wrapping the WorkOS SSO API.
package sso

import (
	"context"
	"net/http"
	"net/url"
)

var (
	// DefaultClient is the client used by GetAuthorizationURL, GetProfileAndToken and
	// Login functions.
	DefaultClient = &Client{}
)

// Configure configures the default client that is used by GetAuthorizationURL,
// GetProfileAndToken and Login.
// It must be called before using those functions.
func Configure(apiKey, clientID string) {
	DefaultClient.APIKey = apiKey
	DefaultClient.ClientID = clientID
}

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func GetAuthorizationURL(opts GetAuthorizationURLOptions) (*url.URL, error) {
	return DefaultClient.GetAuthorizationURL(opts)
}

// GetProfileAndToken returns a profile describing the user that authenticated with
// WorkOS SSO.
func GetProfileAndToken(ctx context.Context, opts GetProfileAndTokenOptions) (ProfileAndToken, error) {
	return DefaultClient.GetProfileAndToken(ctx, opts)
}

// GetProfile returns a profile describing the user that authenticated with
// WorkOS SSO.
func GetProfile(ctx context.Context, opts GetProfileOptions) (Profile, error) {
	return DefaultClient.GetProfile(ctx, opts)
}

// Login return a http.Handler that redirects client to the appropriate
// login provider.
func Login(opts GetAuthorizationURLOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := GetAuthorizationURL(opts)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})
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
