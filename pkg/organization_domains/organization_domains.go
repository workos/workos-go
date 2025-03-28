// Package `organizations` provides a client wrapping the WorkOS Organizations API.
package organization_domains

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Organizations functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Organization Domains requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetOrganizationDomain gets an Organization Domain.
func GetOrganizationDomain(
	ctx context.Context,
	opts GetOrganizationDomainOpts,
) (OrganizationDomain, error) {
	return DefaultClient.GetDomain(ctx, opts)
}

// CreateOrganizationDomain creates an Organization Domain.
func CreateOrganizationDomain(
	ctx context.Context,
	opts CreateOrganizationDomainOpts,
) (OrganizationDomain, error) {
	return DefaultClient.CreateDomain(ctx, opts)
}

// VerifyOrganizationDomain triggers verification for an Organization Domain.
func VerifyOrganizationDomain(
	ctx context.Context,
	opts VerifyOrganizationDomainOpts,
) (OrganizationDomain, error) {
	return DefaultClient.VerifyDomain(ctx, opts)
}
