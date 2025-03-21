// Package `organizations` provides a client wrapping the WorkOS Organizations API.
package organizations

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Organizations functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Organizations requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetOrganization gets an Organization.
func GetOrganization(
	ctx context.Context,
	opts GetOrganizationOpts,
) (Organization, error) {
	return DefaultClient.GetOrganization(ctx, opts)
}

// GetOrganization gets an Organization by its external id
func GetOrganizationByExternalID(
	ctx context.Context,
	opts GetOrganizationByExternalIDOpts,
) (Organization, error) {
	return DefaultClient.GetOrganizationByExternalID(ctx, opts)
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

// UpdateOrganization creates an Organization.
func UpdateOrganization(
	ctx context.Context,
	opts UpdateOrganizationOpts,
) (Organization, error) {
	return DefaultClient.UpdateOrganization(ctx, opts)
}

// DeleteOrganization deletes an Organization.
func DeleteOrganization(
	ctx context.Context,
	opts DeleteOrganizationOpts,
) error {
	return DefaultClient.DeleteOrganization(ctx, opts)
}

// ListOrganizationRoles lists roles for an Organization.
func ListOrganizationRoles(
	ctx context.Context,
	opts ListOrganizationRolesOpts,
) (ListOrganizationRolesResponse, error) {
	return DefaultClient.ListOrganizationRoles(ctx, opts)
}
