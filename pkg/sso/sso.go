// Package `sso` provides a client wrapping the WorkOS SSO API.
package sso

import (
	"context"
	"net/http"
	"net/url"
	"time"
	"encoding/json"
	
)

// Client represents a client that performs Admin Portal requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	ClientID string

	// The http.Client that is used to manage Admin Portal records from WorkOS.
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)
}

// DefaultClient is the client used by SetAPIKey and mfa functions.
var (
	DefaultClient = NewClient("", "")
) //question about this vs var DefaultClient *Client



// NewClient returns a new instance of the Client struct with default values.
func NewClient(apiKey, clientID string) *Client {
    return &Client{
        APIKey:     apiKey,
        ClientID:   clientID,
        Endpoint:   "https://api.workos.com",
        HTTPClient: &http.Client{Timeout: time.Second * 10},
        JSONEncode: json.Marshal,
    }
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
