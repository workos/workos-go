package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Client represents a client that performs Authorization requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage authorization resources from WorkOS.
	// Defaults to http.Client.
	HTTPClient *retryablehttp.HttpClient

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &retryablehttp.HttpClient{Client: http.Client{Timeout: 10 * time.Second}}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

// EnvironmentRole represents a role defined at the environment level.
type EnvironmentRole struct {
	Object           string   `json:"object"`
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Slug             string   `json:"slug"`
	Description      string   `json:"description"`
	Permissions      []string `json:"permissions"`
	ResourceTypeSlug string   `json:"resource_type_slug"`
	Type             string   `json:"type"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

// OrganizationRole represents a role defined at the organization level.
type OrganizationRole struct {
	Object           string   `json:"object"`
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Slug             string   `json:"slug"`
	Description      string   `json:"description"`
	Permissions      []string `json:"permissions"`
	ResourceTypeSlug string   `json:"resource_type_slug"`
	Type             string   `json:"type"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

// Permission represents a permission in the authorization system.
type Permission struct {
	Object           string `json:"object"`
	ID               string `json:"id"`
	Slug             string `json:"slug"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	ResourceTypeSlug string `json:"resource_type_slug"`
	System           bool   `json:"system"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

// AuthorizationResource represents a resource in the authorization system.
type AuthorizationResource struct {
	Object           string `json:"object"`
	ID               string `json:"id"`
	ExternalID       string `json:"external_id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	ResourceTypeSlug string `json:"resource_type_slug"`
	OrganizationID   string `json:"organization_id"`
	ParentResourceID string `json:"parent_resource_id"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

// RoleAssignment represents a role assigned to a membership.
type RoleAssignment struct {
	Object    string                 `json:"object"`
	ID        string                 `json:"id"`
	Role      RoleAssignmentRole     `json:"role"`
	Resource  RoleAssignmentResource `json:"resource"`
	CreatedAt string                 `json:"created_at"`
	UpdatedAt string                 `json:"updated_at"`
}

// RoleAssignmentRole contains the slug of an assigned role.
type RoleAssignmentRole struct {
	Slug string `json:"slug"`
}

// RoleAssignmentResource identifies the resource a role is assigned to.
type RoleAssignmentResource struct {
	ID               string `json:"id"`
	ExternalID       string `json:"external_id"`
	ResourceTypeSlug string `json:"resource_type_slug"`
}

// AuthorizationCheckResult contains the result of an authorization check.
type AuthorizationCheckResult struct {
	Authorized bool `json:"authorized"`
}

// AuthorizationOrganizationMembership represents a membership returned by authorization queries.
type AuthorizationOrganizationMembership struct {
	Object           string                 `json:"object"`
	ID               string                 `json:"id"`
	UserID           string                 `json:"user_id"`
	OrganizationID   string                 `json:"organization_id"`
	Status           string                 `json:"status"`
	CreatedAt        string                 `json:"created_at"`
	UpdatedAt        string                 `json:"updated_at"`
	CustomAttributes map[string]interface{} `json:"custom_attributes"`
}

// List response types

// ListEnvironmentRolesResponse describes the response structure when listing environment roles.
type ListEnvironmentRolesResponse struct {
	Data []EnvironmentRole `json:"data"`
}

// ListOrganizationRolesResponse describes the response structure when listing organization roles.
type ListOrganizationRolesResponse struct {
	Data []OrganizationRole `json:"data"`
}

// ListPermissionsResponse describes the response structure when listing permissions.
type ListPermissionsResponse struct {
	Data         []Permission        `json:"data"`
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

// ListAuthorizationResourcesResponse describes the response structure when listing resources.
type ListAuthorizationResourcesResponse struct {
	Data         []AuthorizationResource `json:"data"`
	ListMetadata common.ListMetadata     `json:"list_metadata"`
}

// ListRoleAssignmentsResponse describes the response structure when listing role assignments.
type ListRoleAssignmentsResponse struct {
	Data         []RoleAssignment    `json:"data"`
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

// ListAuthorizationOrganizationMembershipsResponse describes the response structure when listing memberships.
type ListAuthorizationOrganizationMembershipsResponse struct {
	Data         []AuthorizationOrganizationMembership `json:"data"`
	ListMetadata common.ListMetadata                   `json:"list_metadata"`
}

// Request opts types

// CreateEnvironmentRoleOpts contains the options for creating an environment role.
type CreateEnvironmentRoleOpts struct {
	Slug             string `json:"slug"`
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	ResourceTypeSlug string `json:"resource_type_slug,omitempty"`
}

// GetEnvironmentRoleOpts contains the options for getting an environment role.
type GetEnvironmentRoleOpts struct {
	Slug string `json:"-"`
}

// UpdateEnvironmentRoleOpts contains the options for updating an environment role.
type UpdateEnvironmentRoleOpts struct {
	Slug        string  `json:"-"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description"`
}

// CreateOrganizationRoleOpts contains the options for creating an organization role.
type CreateOrganizationRoleOpts struct {
	OrganizationID string `json:"-"`
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
}

// ListOrganizationRolesOpts contains the options for listing organization roles.
type ListOrganizationRolesOpts struct {
	OrganizationID string `json:"-"`
}

// GetOrganizationRoleOpts contains the options for getting an organization role.
type GetOrganizationRoleOpts struct {
	OrganizationID string `json:"-"`
	Slug           string `json:"-"`
}

// UpdateOrganizationRoleOpts contains the options for updating an organization role.
type UpdateOrganizationRoleOpts struct {
	OrganizationID string  `json:"-"`
	Slug           string  `json:"-"`
	Name           *string `json:"name,omitempty"`
	Description    *string `json:"description"`
}

// DeleteOrganizationRoleOpts contains the options for deleting an organization role.
type DeleteOrganizationRoleOpts struct {
	OrganizationID string `json:"-"`
	Slug           string `json:"-"`
}

// SetEnvironmentRolePermissionsOpts contains the options for setting permissions on an environment role.
type SetEnvironmentRolePermissionsOpts struct {
	Slug        string   `json:"-"`
	Permissions []string `json:"permissions"`
}

// AddEnvironmentRolePermissionOpts contains the options for adding a permission to an environment role.
type AddEnvironmentRolePermissionOpts struct {
	Slug           string `json:"-"`
	PermissionSlug string `json:"slug"`
}

// SetOrganizationRolePermissionsOpts contains the options for setting permissions on an organization role.
type SetOrganizationRolePermissionsOpts struct {
	OrganizationID string   `json:"-"`
	Slug           string   `json:"-"`
	Permissions    []string `json:"permissions"`
}

// AddOrganizationRolePermissionOpts contains the options for adding a permission to an organization role.
type AddOrganizationRolePermissionOpts struct {
	OrganizationID string `json:"-"`
	Slug           string `json:"-"`
	PermissionSlug string `json:"slug"`
}

// RemoveOrganizationRolePermissionOpts contains the options for removing a permission from an organization role.
type RemoveOrganizationRolePermissionOpts struct {
	OrganizationID string `json:"-"`
	Slug           string `json:"-"`
	PermissionSlug string `json:"-"`
}

// CreatePermissionOpts contains the options for creating a permission.
type CreatePermissionOpts struct {
	Slug             string `json:"slug"`
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	ResourceTypeSlug string `json:"resource_type_slug,omitempty"`
}

// ListPermissionsOpts contains the options for listing permissions.
type ListPermissionsOpts struct {
	Limit  int          `url:"limit,omitempty"`
	Before string       `url:"before,omitempty"`
	After  string       `url:"after,omitempty"`
	Order  common.Order `url:"order,omitempty"`
}

// GetPermissionOpts contains the options for getting a permission.
type GetPermissionOpts struct {
	Slug string `json:"-"`
}

// UpdatePermissionOpts contains the options for updating a permission.
type UpdatePermissionOpts struct {
	Slug        string  `json:"-"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description"`
}

// DeletePermissionOpts contains the options for deleting a permission.
type DeletePermissionOpts struct {
	Slug string `json:"-"`
}

// GetAuthorizationResourceOpts contains the options for getting a resource by ID.
type GetAuthorizationResourceOpts struct {
	ResourceID string `json:"-"`
}

// CreateAuthorizationResourceOpts contains the options for creating a resource.
type CreateAuthorizationResourceOpts struct {
	ExternalID               string `json:"external_id"`
	Name                     string `json:"name"`
	Description              string `json:"description,omitempty"`
	ResourceTypeSlug         string `json:"resource_type_slug"`
	OrganizationID           string `json:"organization_id"`
	ParentResourceID         string `json:"parent_resource_id,omitempty"`
	ParentResourceExternalID string `json:"parent_resource_external_id,omitempty"`
	ParentResourceTypeSlug   string `json:"parent_resource_type_slug,omitempty"`
}

// UpdateAuthorizationResourceOpts contains the options for updating a resource.
type UpdateAuthorizationResourceOpts struct {
	ResourceID  string  `json:"-"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description"`
}

// DeleteAuthorizationResourceOpts contains the options for deleting a resource.
type DeleteAuthorizationResourceOpts struct {
	ResourceID    string `json:"-"`
	CascadeDelete bool   `url:"cascade_delete,omitempty"`
}

// ListAuthorizationResourcesOpts contains the options for listing resources.
type ListAuthorizationResourcesOpts struct {
	OrganizationID         string       `url:"organization_id,omitempty"`
	ResourceTypeSlug       string       `url:"resource_type_slug,omitempty"`
	ParentResourceID       string       `url:"parent_resource_id,omitempty"`
	ParentResourceTypeSlug string       `url:"parent_resource_type_slug,omitempty"`
	ParentExternalID       string       `url:"parent_external_id,omitempty"`
	Search                 string       `url:"search,omitempty"`
	Limit                  int          `url:"limit,omitempty"`
	Before                 string       `url:"before,omitempty"`
	After                  string       `url:"after,omitempty"`
	Order                  common.Order `url:"order,omitempty"`
}

// GetResourceByExternalIDOpts contains the options for getting a resource by external ID.
type GetResourceByExternalIDOpts struct {
	OrganizationID   string `json:"-"`
	ResourceTypeSlug string `json:"-"`
	ExternalID       string `json:"-"`
}

// UpdateResourceByExternalIDOpts contains the options for updating a resource by external ID.
type UpdateResourceByExternalIDOpts struct {
	OrganizationID   string  `json:"-"`
	ResourceTypeSlug string  `json:"-"`
	ExternalID       string  `json:"-"`
	Name             *string `json:"name,omitempty"`
	Description      *string `json:"description"`
}

// DeleteResourceByExternalIDOpts contains the options for deleting a resource by external ID.
type DeleteResourceByExternalIDOpts struct {
	OrganizationID   string `json:"-"`
	ResourceTypeSlug string `json:"-"`
	ExternalID       string `json:"-"`
	CascadeDelete    bool   `url:"cascade_delete,omitempty"`
}

// AuthorizationCheckOpts contains the options for performing an authorization check.
type AuthorizationCheckOpts struct {
	OrganizationMembershipID string `json:"-"`
	PermissionSlug           string `json:"permission_slug"`
	ResourceID               string `json:"resource_id,omitempty"`
	ResourceExternalID       string `json:"resource_external_id,omitempty"`
	ResourceTypeSlug         string `json:"resource_type_slug,omitempty"`
}

// ListRoleAssignmentsOpts contains the options for listing role assignments.
type ListRoleAssignmentsOpts struct {
	OrganizationMembershipID string       `json:"-"`
	Limit                    int          `url:"limit,omitempty"`
	Before                   string       `url:"before,omitempty"`
	After                    string       `url:"after,omitempty"`
	Order                    common.Order `url:"order,omitempty"`
}

// AssignRoleOpts contains the options for assigning a role.
type AssignRoleOpts struct {
	OrganizationMembershipID string `json:"-"`
	RoleSlug                 string `json:"role_slug"`
	ResourceID               string `json:"resource_id,omitempty"`
	ResourceExternalID       string `json:"resource_external_id,omitempty"`
	ResourceTypeSlug         string `json:"resource_type_slug,omitempty"`
}

// RemoveRoleOpts contains the options for removing a role.
type RemoveRoleOpts struct {
	OrganizationMembershipID string `json:"-"`
	RoleSlug                 string `json:"role_slug"`
	ResourceID               string `json:"resource_id,omitempty"`
	ResourceExternalID       string `json:"resource_external_id,omitempty"`
	ResourceTypeSlug         string `json:"resource_type_slug,omitempty"`
}

// RemoveRoleAssignmentOpts contains the options for removing a role assignment by ID.
type RemoveRoleAssignmentOpts struct {
	OrganizationMembershipID string `json:"-"`
	RoleAssignmentID         string `json:"-"`
}

// ListResourcesForMembershipOpts contains the options for listing resources accessible by a membership.
type ListResourcesForMembershipOpts struct {
	OrganizationMembershipID string       `json:"-"`
	PermissionSlug           string       `url:"permission_slug"`
	ParentResourceID         string       `url:"parent_resource_id,omitempty"`
	ParentResourceTypeSlug   string       `url:"parent_resource_type_slug,omitempty"`
	ParentResourceExternalID string       `url:"parent_resource_external_id,omitempty"`
	Limit                    int          `url:"limit,omitempty"`
	Before                   string       `url:"before,omitempty"`
	After                    string       `url:"after,omitempty"`
	Order                    common.Order `url:"order,omitempty"`
}

// ListMembershipsForResourceOpts contains the options for listing memberships with access to a resource.
type ListMembershipsForResourceOpts struct {
	ResourceID     string       `json:"-"`
	PermissionSlug string       `url:"permission_slug"`
	Assignment     string       `url:"assignment,omitempty"`
	Limit          int          `url:"limit,omitempty"`
	Before         string       `url:"before,omitempty"`
	After          string       `url:"after,omitempty"`
	Order          common.Order `url:"order,omitempty"`
}

// ListMembershipsForResourceByExternalIDOpts contains the options for listing memberships by resource external ID.
type ListMembershipsForResourceByExternalIDOpts struct {
	OrganizationID   string       `json:"-"`
	ResourceTypeSlug string       `json:"-"`
	ExternalID       string       `json:"-"`
	PermissionSlug   string       `url:"permission_slug"`
	Assignment       string       `url:"assignment,omitempty"`
	Limit            int          `url:"limit,omitempty"`
	Before           string       `url:"before,omitempty"`
	After            string       `url:"after,omitempty"`
	Order            common.Order `url:"order,omitempty"`
}

// Stub method implementations

// CreateEnvironmentRole creates a new environment role.
func (c *Client) CreateEnvironmentRole(ctx context.Context, opts CreateEnvironmentRoleOpts) (EnvironmentRole, error) {
	return EnvironmentRole{}, errors.New("not implemented")
}

// ListEnvironmentRoles lists all environment roles.
func (c *Client) ListEnvironmentRoles(ctx context.Context) (ListEnvironmentRolesResponse, error) {
	return ListEnvironmentRolesResponse{}, errors.New("not implemented")
}

// GetEnvironmentRole gets an environment role by slug.
func (c *Client) GetEnvironmentRole(ctx context.Context, opts GetEnvironmentRoleOpts) (EnvironmentRole, error) {
	return EnvironmentRole{}, errors.New("not implemented")
}

// UpdateEnvironmentRole updates an environment role.
func (c *Client) UpdateEnvironmentRole(ctx context.Context, opts UpdateEnvironmentRoleOpts) (EnvironmentRole, error) {
	return EnvironmentRole{}, errors.New("not implemented")
}

// CreateOrganizationRole creates a new organization role.
func (c *Client) CreateOrganizationRole(ctx context.Context, opts CreateOrganizationRoleOpts) (OrganizationRole, error) {
	return OrganizationRole{}, errors.New("not implemented")
}

// ListOrganizationRoles lists all roles for an organization.
func (c *Client) ListOrganizationRoles(ctx context.Context, opts ListOrganizationRolesOpts) (ListOrganizationRolesResponse, error) {
	return ListOrganizationRolesResponse{}, errors.New("not implemented")
}

// GetOrganizationRole gets an organization role by slug.
func (c *Client) GetOrganizationRole(ctx context.Context, opts GetOrganizationRoleOpts) (OrganizationRole, error) {
	return OrganizationRole{}, errors.New("not implemented")
}

// UpdateOrganizationRole updates an organization role.
func (c *Client) UpdateOrganizationRole(ctx context.Context, opts UpdateOrganizationRoleOpts) (OrganizationRole, error) {
	return OrganizationRole{}, errors.New("not implemented")
}

// DeleteOrganizationRole deletes an organization role.
func (c *Client) DeleteOrganizationRole(ctx context.Context, opts DeleteOrganizationRoleOpts) error {
	return errors.New("not implemented")
}

// SetEnvironmentRolePermissions sets permissions for an environment role.
func (c *Client) SetEnvironmentRolePermissions(ctx context.Context, opts SetEnvironmentRolePermissionsOpts) (EnvironmentRole, error) {
	return EnvironmentRole{}, errors.New("not implemented")
}

// AddEnvironmentRolePermission adds a permission to an environment role.
func (c *Client) AddEnvironmentRolePermission(ctx context.Context, opts AddEnvironmentRolePermissionOpts) (EnvironmentRole, error) {
	return EnvironmentRole{}, errors.New("not implemented")
}

// SetOrganizationRolePermissions sets permissions for an organization role.
func (c *Client) SetOrganizationRolePermissions(ctx context.Context, opts SetOrganizationRolePermissionsOpts) (OrganizationRole, error) {
	return OrganizationRole{}, errors.New("not implemented")
}

// AddOrganizationRolePermission adds a permission to an organization role.
func (c *Client) AddOrganizationRolePermission(ctx context.Context, opts AddOrganizationRolePermissionOpts) (OrganizationRole, error) {
	return OrganizationRole{}, errors.New("not implemented")
}

// RemoveOrganizationRolePermission removes a permission from an organization role.
func (c *Client) RemoveOrganizationRolePermission(ctx context.Context, opts RemoveOrganizationRolePermissionOpts) error {
	return errors.New("not implemented")
}

// CreatePermission creates a new permission.
func (c *Client) CreatePermission(ctx context.Context, opts CreatePermissionOpts) (Permission, error) {
	return Permission{}, errors.New("not implemented")
}

// ListPermissions lists all permissions.
func (c *Client) ListPermissions(ctx context.Context, opts ListPermissionsOpts) (ListPermissionsResponse, error) {
	return ListPermissionsResponse{}, errors.New("not implemented")
}

// GetPermission gets a permission by slug.
func (c *Client) GetPermission(ctx context.Context, opts GetPermissionOpts) (Permission, error) {
	return Permission{}, errors.New("not implemented")
}

// UpdatePermission updates a permission.
func (c *Client) UpdatePermission(ctx context.Context, opts UpdatePermissionOpts) (Permission, error) {
	return Permission{}, errors.New("not implemented")
}

// DeletePermission deletes a permission.
func (c *Client) DeletePermission(ctx context.Context, opts DeletePermissionOpts) error {
	return errors.New("not implemented")
}

// GetResource gets a resource by ID.
func (c *Client) GetResource(ctx context.Context, opts GetAuthorizationResourceOpts) (AuthorizationResource, error) {
	return AuthorizationResource{}, errors.New("not implemented")
}

// CreateResource creates a new resource.
func (c *Client) CreateResource(ctx context.Context, opts CreateAuthorizationResourceOpts) (AuthorizationResource, error) {
	return AuthorizationResource{}, errors.New("not implemented")
}

// UpdateResource updates a resource.
func (c *Client) UpdateResource(ctx context.Context, opts UpdateAuthorizationResourceOpts) (AuthorizationResource, error) {
	return AuthorizationResource{}, errors.New("not implemented")
}

// DeleteResource deletes a resource.
func (c *Client) DeleteResource(ctx context.Context, opts DeleteAuthorizationResourceOpts) error {
	return errors.New("not implemented")
}

// ListResources lists resources with optional filters.
func (c *Client) ListResources(ctx context.Context, opts ListAuthorizationResourcesOpts) (ListAuthorizationResourcesResponse, error) {
	return ListAuthorizationResourcesResponse{}, errors.New("not implemented")
}

// GetResourceByExternalID gets a resource by its external ID.
func (c *Client) GetResourceByExternalID(ctx context.Context, opts GetResourceByExternalIDOpts) (AuthorizationResource, error) {
	return AuthorizationResource{}, errors.New("not implemented")
}

// UpdateResourceByExternalID updates a resource by its external ID.
func (c *Client) UpdateResourceByExternalID(ctx context.Context, opts UpdateResourceByExternalIDOpts) (AuthorizationResource, error) {
	return AuthorizationResource{}, errors.New("not implemented")
}

// DeleteResourceByExternalID deletes a resource by its external ID.
func (c *Client) DeleteResourceByExternalID(ctx context.Context, opts DeleteResourceByExternalIDOpts) error {
	return errors.New("not implemented")
}

// Check performs an authorization check.
func (c *Client) Check(ctx context.Context, opts AuthorizationCheckOpts) (AuthorizationCheckResult, error) {
	return AuthorizationCheckResult{}, errors.New("not implemented")
}

// ListRoleAssignments lists role assignments for a membership.
func (c *Client) ListRoleAssignments(ctx context.Context, opts ListRoleAssignmentsOpts) (ListRoleAssignmentsResponse, error) {
	return ListRoleAssignmentsResponse{}, errors.New("not implemented")
}

// AssignRole assigns a role to a membership.
func (c *Client) AssignRole(ctx context.Context, opts AssignRoleOpts) (RoleAssignment, error) {
	return RoleAssignment{}, errors.New("not implemented")
}

// RemoveRole removes a role from a membership.
func (c *Client) RemoveRole(ctx context.Context, opts RemoveRoleOpts) error {
	return errors.New("not implemented")
}

// RemoveRoleAssignment removes a role assignment by ID.
func (c *Client) RemoveRoleAssignment(ctx context.Context, opts RemoveRoleAssignmentOpts) error {
	return errors.New("not implemented")
}

// ListResourcesForMembership lists resources accessible by a membership.
func (c *Client) ListResourcesForMembership(ctx context.Context, opts ListResourcesForMembershipOpts) (ListAuthorizationResourcesResponse, error) {
	return ListAuthorizationResourcesResponse{}, errors.New("not implemented")
}

// ListMembershipsForResource lists memberships with access to a resource.
func (c *Client) ListMembershipsForResource(ctx context.Context, opts ListMembershipsForResourceOpts) (ListAuthorizationOrganizationMembershipsResponse, error) {
	return ListAuthorizationOrganizationMembershipsResponse{}, errors.New("not implemented")
}

// ListMembershipsForResourceByExternalID lists memberships with access to a resource identified by external ID.
func (c *Client) ListMembershipsForResourceByExternalID(ctx context.Context, opts ListMembershipsForResourceByExternalIDOpts) (ListAuthorizationOrganizationMembershipsResponse, error) {
	return ListAuthorizationOrganizationMembershipsResponse{}, errors.New("not implemented")
}
