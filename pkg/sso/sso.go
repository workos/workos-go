// Package sso provide functions and client to communicate with WorkOS SSO API.
package sso

import (
	"context"
	"net/http"
	"net/url"
)

const (
	version = "0.0.1"
)

var (
	// DefaultClient is the client used by SetAPIKey, GetAuthorizationURL,
	// GetProfile and Login functions.
	DefaultClient = &Client{}
)

// SetAPIKey set the api key to use with
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
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
			w.WriteHeader(http.StatusInsufficientStorage)
			w.Write([]byte(err.Error()))
			return
		}

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})
}
