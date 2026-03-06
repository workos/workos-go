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

// CreateEnvironmentRole creates a new environment role.
func CreateEnvironmentRole(
	ctx context.Context,
	opts CreateEnvironmentRoleOpts,
) (EnvironmentRole, error) {
	return DefaultClient.CreateEnvironmentRole(ctx, opts)
}

// ListEnvironmentRoles lists all environment roles.
func ListEnvironmentRoles(
	ctx context.Context,
) (ListEnvironmentRolesResponse, error) {
	return DefaultClient.ListEnvironmentRoles(ctx)
}

// GetEnvironmentRole gets an environment role by slug.
func GetEnvironmentRole(
	ctx context.Context,
	opts GetEnvironmentRoleOpts,
) (EnvironmentRole, error) {
	return DefaultClient.GetEnvironmentRole(ctx, opts)
}

// UpdateEnvironmentRole updates an environment role.
func UpdateEnvironmentRole(
	ctx context.Context,
	opts UpdateEnvironmentRoleOpts,
) (EnvironmentRole, error) {
	return DefaultClient.UpdateEnvironmentRole(ctx, opts)
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

// SetEnvironmentRolePermissions sets permissions for an environment role.
func SetEnvironmentRolePermissions(
	ctx context.Context,
	opts SetEnvironmentRolePermissionsOpts,
) (EnvironmentRole, error) {
	return DefaultClient.SetEnvironmentRolePermissions(ctx, opts)
}

// AddEnvironmentRolePermission adds a permission to an environment role.
func AddEnvironmentRolePermission(
	ctx context.Context,
	opts AddEnvironmentRolePermissionOpts,
) (EnvironmentRole, error) {
	return DefaultClient.AddEnvironmentRolePermission(ctx, opts)
}

// SetOrganizationRolePermissions sets permissions for an organization role.
func SetOrganizationRolePermissions(
	ctx context.Context,
	opts SetOrganizationRolePermissionsOpts,
) (OrganizationRole, error) {
	return DefaultClient.SetOrganizationRolePermissions(ctx, opts)
}

// AddOrganizationRolePermission adds a permission to an organization role.
func AddOrganizationRolePermission(
	ctx context.Context,
	opts AddOrganizationRolePermissionOpts,
) (OrganizationRole, error) {
	return DefaultClient.AddOrganizationRolePermission(ctx, opts)
}

// RemoveOrganizationRolePermission removes a permission from an organization role.
func RemoveOrganizationRolePermission(
	ctx context.Context,
	opts RemoveOrganizationRolePermissionOpts,
) error {
	return DefaultClient.RemoveOrganizationRolePermission(ctx, opts)
}

// CreatePermission creates a new permission.
func CreatePermission(
	ctx context.Context,
	opts CreatePermissionOpts,
) (Permission, error) {
	return DefaultClient.CreatePermission(ctx, opts)
}

// ListPermissions lists all permissions.
func ListPermissions(
	ctx context.Context,
	opts ListPermissionsOpts,
) (ListPermissionsResponse, error) {
	return DefaultClient.ListPermissions(ctx, opts)
}

// GetPermission gets a permission by slug.
func GetPermission(
	ctx context.Context,
	opts GetPermissionOpts,
) (Permission, error) {
	return DefaultClient.GetPermission(ctx, opts)
}

// UpdatePermission updates a permission.
func UpdatePermission(
	ctx context.Context,
	opts UpdatePermissionOpts,
) (Permission, error) {
	return DefaultClient.UpdatePermission(ctx, opts)
}

// DeletePermission deletes a permission.
func DeletePermission(
	ctx context.Context,
	opts DeletePermissionOpts,
) error {
	return DefaultClient.DeletePermission(ctx, opts)
}

// GetResource gets a resource by ID.
func GetResource(
	ctx context.Context,
	opts GetAuthorizationResourceOpts,
) (AuthorizationResource, error) {
	return DefaultClient.GetResource(ctx, opts)
}

// CreateResource creates a new resource.
func CreateResource(
	ctx context.Context,
	opts CreateAuthorizationResourceOpts,
) (AuthorizationResource, error) {
	return DefaultClient.CreateResource(ctx, opts)
}

// UpdateResource updates a resource.
func UpdateResource(
	ctx context.Context,
	opts UpdateAuthorizationResourceOpts,
) (AuthorizationResource, error) {
	return DefaultClient.UpdateResource(ctx, opts)
}

// DeleteResource deletes a resource.
func DeleteResource(
	ctx context.Context,
	opts DeleteAuthorizationResourceOpts,
) error {
	return DefaultClient.DeleteResource(ctx, opts)
}

// ListResources lists resources with optional filters.
func ListResources(
	ctx context.Context,
	opts ListAuthorizationResourcesOpts,
) (ListAuthorizationResourcesResponse, error) {
	return DefaultClient.ListResources(ctx, opts)
}

// GetResourceByExternalID gets a resource by its external ID.
func GetResourceByExternalID(
	ctx context.Context,
	opts GetResourceByExternalIDOpts,
) (AuthorizationResource, error) {
	return DefaultClient.GetResourceByExternalID(ctx, opts)
}

// UpdateResourceByExternalID updates a resource by its external ID.
func UpdateResourceByExternalID(
	ctx context.Context,
	opts UpdateResourceByExternalIDOpts,
) (AuthorizationResource, error) {
	return DefaultClient.UpdateResourceByExternalID(ctx, opts)
}

// DeleteResourceByExternalID deletes a resource by its external ID.
func DeleteResourceByExternalID(
	ctx context.Context,
	opts DeleteResourceByExternalIDOpts,
) error {
	return DefaultClient.DeleteResourceByExternalID(ctx, opts)
}

// Check performs an authorization check.
func Check(
	ctx context.Context,
	opts AuthorizationCheckOpts,
) (AuthorizationCheckResult, error) {
	return DefaultClient.Check(ctx, opts)
}

// ListRoleAssignments lists role assignments for a membership.
func ListRoleAssignments(
	ctx context.Context,
	opts ListRoleAssignmentsOpts,
) (ListRoleAssignmentsResponse, error) {
	return DefaultClient.ListRoleAssignments(ctx, opts)
}

// AssignRole assigns a role to a membership.
func AssignRole(
	ctx context.Context,
	opts AssignRoleOpts,
) (RoleAssignment, error) {
	return DefaultClient.AssignRole(ctx, opts)
}

// RemoveRole removes a role from a membership.
func RemoveRole(
	ctx context.Context,
	opts RemoveRoleOpts,
) error {
	return DefaultClient.RemoveRole(ctx, opts)
}

// RemoveRoleAssignment removes a role assignment by ID.
func RemoveRoleAssignment(
	ctx context.Context,
	opts RemoveRoleAssignmentOpts,
) error {
	return DefaultClient.RemoveRoleAssignment(ctx, opts)
}

// ListResourcesForMembership lists resources accessible by a membership.
func ListResourcesForMembership(
	ctx context.Context,
	opts ListResourcesForMembershipOpts,
) (ListAuthorizationResourcesResponse, error) {
	return DefaultClient.ListResourcesForMembership(ctx, opts)
}

// ListMembershipsForResource lists memberships with access to a resource.
func ListMembershipsForResource(
	ctx context.Context,
	opts ListMembershipsForResourceOpts,
) (ListAuthorizationOrganizationMembershipsResponse, error) {
	return DefaultClient.ListMembershipsForResource(ctx, opts)
}

// ListMembershipsForResourceByExternalID lists memberships with access to a resource identified by external ID.
func ListMembershipsForResourceByExternalID(
	ctx context.Context,
	opts ListMembershipsForResourceByExternalIDOpts,
) (ListAuthorizationOrganizationMembershipsResponse, error) {
	return DefaultClient.ListMembershipsForResourceByExternalID(ctx, opts)
}
