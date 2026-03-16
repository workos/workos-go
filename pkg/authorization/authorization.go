package authorization

import "context"

// DefaultClient is the client used by SetAPIKey and Authorization functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Authorization requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// CreateOrganizationRole creates a new organization role.
func CreateOrganizationRole(
	ctx context.Context,
	opts CreateOrganizationRoleOpts,
) (OrganizationRole, error) {
	return DefaultClient.CreateOrganizationRole(ctx, opts)
}

// ListOrganizationRoles lists all roles for an organization.
func ListOrganizationRoles(
	ctx context.Context,
	opts ListOrganizationRolesOpts,
) (ListOrganizationRolesResponse, error) {
	return DefaultClient.ListOrganizationRoles(ctx, opts)
}

// GetOrganizationRole gets an organization role by slug.
func GetOrganizationRole(
	ctx context.Context,
	opts GetOrganizationRoleOpts,
) (OrganizationRole, error) {
	return DefaultClient.GetOrganizationRole(ctx, opts)
}

// UpdateOrganizationRole updates an organization role.
func UpdateOrganizationRole(
	ctx context.Context,
	opts UpdateOrganizationRoleOpts,
) (OrganizationRole, error) {
	return DefaultClient.UpdateOrganizationRole(ctx, opts)
}

// DeleteOrganizationRole deletes an organization role.
func DeleteOrganizationRole(
	ctx context.Context,
	opts DeleteOrganizationRoleOpts,
) error {
	return DefaultClient.DeleteOrganizationRole(ctx, opts)
}
