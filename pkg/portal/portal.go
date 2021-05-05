// Package `portal` provides a client wrapping the WorkOS Admin Portal API.
package portal

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Admin Portal functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Admin Portal requests.
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

// CreateOrganization creates an Organization.
func CreateOrganization(
	ctx context.Context,
	opts CreateOrganizationOpts,
) (Organization, error) {
	return DefaultClient.CreateOrganization(ctx, opts)
}

// GenerateLink generates an ephemeral link to the Admin Portal
func GenerateLink(
	ctx context.Context,
	opts GenerateLinkOpts,
) (string, error) {
	return DefaultClient.GenerateLink(ctx, opts)
}

// UpdateOrganization creates an Organization.
func UpdateOrganization(
	ctx context.Context,
	opts UpdateOrganizationOpts,
) (Organization, error) {
	return DefaultClient.UpdateOrganization(ctx, opts)
}
