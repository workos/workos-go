// Package `organizations` provides a client wrapping the WorkOS OAuthCredentials API.
package oauthcredentials

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and OAuthCredentials functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for OAuthCredentials requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetOAuthCredential gets an OAuthCredential.
func GetOAuthCredential(
	ctx context.Context,
	opts GetOAuthCredentialOpts,
) (OAuthCredential, error) {
	return DefaultClient.GetOAuthCredential(ctx, opts)
}

// ListOAuthCredentials gets a list of OAuthCredentials.
func ListOAuthCredentials(
	ctx context.Context,
	opts ListOAuthCredentialsOpts,
) (ListOAuthCredentialsResponse, error) {
	return DefaultClient.ListOAuthCredentials(ctx, opts)
}

// UpdateOAuthCredential creates an OAuthCredential.
func UpdateOAuthCredential(
	ctx context.Context,
	opts UpdateOAuthCredentialOpts,
) (OAuthCredential, error) {
	return DefaultClient.UpdateOAuthCredential(ctx, opts)
}

// CreateOAuthCredential creates an OAuthCredential.
func CreateOAuthCredential(
	ctx context.Context,
	opts CreateOAuthCredentialOpts,
) (OAuthCredential, error) {
	return DefaultClient.CreateOAuthCredential(ctx, opts)
}
