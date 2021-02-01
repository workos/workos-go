// Package `sso` provides a client wrapping the WorkOS SSO API.
package sso

import (
	"context"
	"net/http"
	"net/url"
)

var (
	// DefaultClient is the client used by GetAuthorizationURL, GetProfile and
	// Login functions.
	DefaultClient = &Client{}
)

// Configure configures the default client that is used by GetAuthorizationURL,
// GetProfile and Login.
// It must be called before using those functions.
// Deprecated: Please pass clientID as an argument, not projectID.
func Configure(apiKey, clientID string) {
	DefaultClient.APIKey = apiKey
	DefaultClient.ClientID = clientID
}

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func GetAuthorizationURL(opts GetAuthorizationURLOptions) (*url.URL, error) {
	return DefaultClient.GetAuthorizationURL(opts)
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

// PromoteDraftConnection promotes a draft connection created via the WorkOS.js Embed
// such that the Enterprise users can begin signing into your application.
//
// Deprecated: Use `CreateConnection` instead.
func PromoteDraftConnection(ctx context.Context, opts PromoteDraftConnectionOptions) error {
	return DefaultClient.PromoteDraftConnection(ctx, opts)
}

// CreateConnection promotes a Draft Connection created via the WorkOS.js widget.
func CreateConnection(ctx context.Context, opts CreateConnectionOpts) (Connection, error) {
	return DefaultClient.CreateConnection(ctx, opts)
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

func DeleteConnection(
	ctx context.Context,
	opts DeleteConnectionOpts,
) error {
	return DefaultClient.DeleteConnection(ctx, opts)
}
