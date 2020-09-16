// Package portal is a package to manage the WorkOS Admin Portal
//
// You first need to configure your Admin Portal settings at
// https://dashboard.workos.com/admin-portal.
//
// Example:
//	func main() {
//		portal.SetAPIKey("my_api_key")
//
//		organizations, err := portal.ListOrganizations(
//			context.Background(),
//			portal.ListOrganizationsOpts{
//				Domains: []string{"foo-corp.com"}
//			},
//		)
//	}
package portal

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Directory Sync functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Directory Sync requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// ListOrganizations gets a list of Organizations.
func ListOrganizations(
	ctx context.Context,
	opts ListOrganizationsOpts,
) (ListOrganizationsResponse, error) {
	return DefaultClient.ListOrganizations(ctx, opts)
}

// GenerateLink generates an ephemeral link to the Admin Portal
func GenerateLink(
	ctx context.Context,
	opts GenerateLinkOpts,
) (string, error) {
	return DefaultClient.GenerateLink(ctx, opts)
}
