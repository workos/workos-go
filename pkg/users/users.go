// Package `users` provides a client wrapping the WorkOS SSO API.
package users

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
