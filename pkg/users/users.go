// Package users provides a client wrapping the WorkOS User Management API.
package users

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
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
	DefaultClient = NewClient("")
)

// NewClient returns a new instance of the Client struct with default values.
func NewClient(apiKey) *Client {
	return &Client{
		APIKey:     apiKey,
		ClientID:   clientID,
		Endpoint:   "https://api.workos.com",
		HTTPClient: &http.Client{Timeout: time.Second * 10},
		JSONEncode: json.Marshal,
	}
}

// GetUser gets a User.
func GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (User, error) {
	return DefaultClient.GetUser(ctx, opts)
}

func AuthenticateUserWithPassword(
	ctx context.Context,
	opts AuthenticateUserWithPasswordOpts,
) (AuthenticationResponse, error){
	return DefaultClient.AuthenticateUserWithPassword(ctx, opts)
}