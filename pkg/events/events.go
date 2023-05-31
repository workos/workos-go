// Package `events` provides a client wrapping the WorkOS Events API.
package events

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Event functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Events requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetEvents gets a list of Events for an environment.
func GetEvents(
	ctx context.Context,
	opts GetEventsOpts,
) (GetEventsResponse, error) {
	return DefaultClient.GetEvents(ctx, opts)
}
