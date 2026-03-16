package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v6/internal/workos"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
	"github.com/workos/workos-go/v6/pkg/workos_errors"
)

// DefaultListSize is the default number of records to return in list responses.
const DefaultListSize = 10

// Authorization API path segments.
const (
	authorizationRolesPath                   = "authorization/roles"
	authorizationPermissionsPath             = "authorization/permissions"
	authorizationResourcesPath               = "authorization/resources"
	authorizationOrganizationsPath           = "authorization/organizations"
	authorizationOrganizationMembershipsPath = "authorization/organization_memberships"
)

// Client represents a client that performs Authorization requests to the WorkOS API.
// All exported fields must be set before the first method call; the client is not safe for concurrent field mutation.
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

// ResourceIdentifier identifies a resource by Id or by external Id and type slug.
type ResourceIdentifier interface {
	resourceIdentifierParams() map[string]interface{}
}

// ResourceIdentifierById identifies a resource by its internal Id.
type ResourceIdentifierById struct {
	ResourceId string
}

func (r ResourceIdentifierById) resourceIdentifierParams() map[string]interface{} {
	return map[string]interface{}{"resource_id": r.ResourceId}
}

// ResourceIdentifierByExternalId identifies a resource by external Id and type slug.
type ResourceIdentifierByExternalId struct {
	ResourceExternalId string
	ResourceTypeSlug   string
}

func (r ResourceIdentifierByExternalId) resourceIdentifierParams() map[string]interface{} {
	return map[string]interface{}{
		"resource_external_id": r.ResourceExternalId,
		"resource_type_slug":   r.ResourceTypeSlug,
	}
}

// ParentResourceIdentifier identifies a parent resource by Id or by external Id and type slug.
type ParentResourceIdentifier interface {
	parentResourceIdentifierParams() map[string]interface{}
}

// ParentResourceIdentifierById identifies a parent resource by its internal Id.
type ParentResourceIdentifierById struct {
	ParentResourceId string
}

func (r ParentResourceIdentifierById) parentResourceIdentifierParams() map[string]interface{} {
	return map[string]interface{}{"parent_resource_id": r.ParentResourceId}
}

// ParentResourceIdentifierByExternalId identifies a parent resource by external Id and type slug.
type ParentResourceIdentifierByExternalId struct {
	ParentResourceExternalId string
	ParentResourceTypeSlug   string
}

func (r ParentResourceIdentifierByExternalId) parentResourceIdentifierParams() map[string]interface{} {
	return map[string]interface{}{
		"parent_resource_external_id": r.ParentResourceExternalId,
		"parent_resource_type_slug":   r.ParentResourceTypeSlug,
	}
}

// EnvironmentRole represents a role defined at the environment level.
type EnvironmentRole struct {
	Object           string   `json:"object"`
	Id               string   `json:"id"`
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
	Id               string   `json:"id"`
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
	Id               string `json:"id"`
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
	Id               string `json:"id"`
	ExternalId       string `json:"external_id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	ResourceTypeSlug string `json:"resource_type_slug"`
	OrganizationId   string `json:"organization_id"`
	ParentResourceId string `json:"parent_resource_id"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

// RoleAssignment represents a role assigned to a membership.
type RoleAssignment struct {
	Object    string                 `json:"object"`
	Id        string                 `json:"id"`
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
	Id               string `json:"id"`
	ExternalId       string `json:"external_id"`
	ResourceTypeSlug string `json:"resource_type_slug"`
}

// AuthorizationCheckResult contains the result of an authorization check.
type AuthorizationCheckResult struct {
	Authorized bool `json:"authorized"`
}

// AuthorizationOrganizationMembership represents a membership returned by authorization queries.
type AuthorizationOrganizationMembership struct {
	Object           string                 `json:"object"`
	Id               string                 `json:"id"`
	UserId           string                 `json:"user_id"`
	OrganizationId   string                 `json:"organization_id"`
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
	Description *string `json:"description"` // omitempty intentionally omitted to allow null-clearing
}

// CreateOrganizationRoleOpts contains the options for creating an organization role.
type CreateOrganizationRoleOpts struct {
	OrganizationId string `json:"-"`
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
}

// ListOrganizationRolesOpts contains the options for listing organization roles.
type ListOrganizationRolesOpts struct {
	OrganizationId string `json:"-"`
}

// GetOrganizationRoleOpts contains the options for getting an organization role.
type GetOrganizationRoleOpts struct {
	OrganizationId string `json:"-"`
	Slug           string `json:"-"`
}

// UpdateOrganizationRoleOpts contains the options for updating an organization role.
type UpdateOrganizationRoleOpts struct {
	OrganizationId string  `json:"-"`
	Slug           string  `json:"-"`
	Name           *string `json:"name,omitempty"`
	Description    *string `json:"description"` // omitempty intentionally omitted to allow null-clearing
}

// DeleteOrganizationRoleOpts contains the options for deleting an organization role.
type DeleteOrganizationRoleOpts struct {
	OrganizationId string `json:"-"`
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
	OrganizationId string   `json:"-"`
	Slug           string   `json:"-"`
	Permissions    []string `json:"permissions"`
}

// AddOrganizationRolePermissionOpts contains the options for adding a permission to an organization role.
type AddOrganizationRolePermissionOpts struct {
	OrganizationId string `json:"-"`
	Slug           string `json:"-"`
	PermissionSlug string `json:"slug"`
}

// RemoveOrganizationRolePermissionOpts contains the options for removing a permission from an organization role.
type RemoveOrganizationRolePermissionOpts struct {
	OrganizationId string `json:"-"`
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
	Description *string `json:"description"` // omitempty intentionally omitted to allow null-clearing
}

// DeletePermissionOpts contains the options for deleting a permission.
type DeletePermissionOpts struct {
	Slug string `json:"-"`
}

// GetAuthorizationResourceOpts contains the options for getting a resource by Id.
type GetAuthorizationResourceOpts struct {
	ResourceId string `json:"-"`
}

// CreateAuthorizationResourceOpts contains the options for creating a resource.
type CreateAuthorizationResourceOpts struct {
	ExternalId       string                   `json:"external_id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description,omitempty"`
	ResourceTypeSlug string                   `json:"resource_type_slug"`
	OrganizationId   string                   `json:"organization_id"`
	Parent           ParentResourceIdentifier `json:"-"`
}

// UpdateAuthorizationResourceOpts contains the options for updating a resource.
type UpdateAuthorizationResourceOpts struct {
	ResourceId  string  `json:"-"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description"` // omitempty intentionally omitted to allow null-clearing
}

// DeleteAuthorizationResourceOpts contains the options for deleting a resource.
type DeleteAuthorizationResourceOpts struct {
	ResourceId    string `json:"-"`
	CascadeDelete bool   `url:"cascade_delete,omitempty"`
}

// ListAuthorizationResourcesOpts contains the options for listing resources.
type ListAuthorizationResourcesOpts struct {
	OrganizationId         string       `url:"organization_id,omitempty"`
	ResourceTypeSlug       string       `url:"resource_type_slug,omitempty"`
	ParentResourceId       string       `url:"parent_resource_id,omitempty"`
	ParentResourceTypeSlug string       `url:"parent_resource_type_slug,omitempty"`
	ParentExternalId       string       `url:"parent_external_id,omitempty"`
	Search                 string       `url:"search,omitempty"`
	Limit                  int          `url:"limit,omitempty"`
	Before                 string       `url:"before,omitempty"`
	After                  string       `url:"after,omitempty"`
	Order                  common.Order `url:"order,omitempty"`
}

// GetResourceByExternalIdOpts contains the options for getting a resource by external Id.
type GetResourceByExternalIdOpts struct {
	OrganizationId   string `json:"-"`
	ResourceTypeSlug string `json:"-"`
	ExternalId       string `json:"-"`
}

// UpdateResourceByExternalIdOpts contains the options for updating a resource by external Id.
type UpdateResourceByExternalIdOpts struct {
	OrganizationId   string  `json:"-"`
	ResourceTypeSlug string  `json:"-"`
	ExternalId       string  `json:"-"`
	Name             *string `json:"name,omitempty"`
	Description      *string `json:"description"` // omitempty intentionally omitted to allow null-clearing
}

// DeleteResourceByExternalIdOpts contains the options for deleting a resource by external Id.
type DeleteResourceByExternalIdOpts struct {
	OrganizationId   string `json:"-"`
	ResourceTypeSlug string `json:"-"`
	ExternalId       string `json:"-"`
	CascadeDelete    bool   `url:"cascade_delete,omitempty"`
}

// AuthorizationCheckOpts contains the options for performing an authorization check.
type AuthorizationCheckOpts struct {
	OrganizationMembershipId string             `json:"-"`
	PermissionSlug           string             `json:"permission_slug"`
	Resource                 ResourceIdentifier `json:"-"`
}

// ListRoleAssignmentsOpts contains the options for listing role assignments.
type ListRoleAssignmentsOpts struct {
	OrganizationMembershipId string       `json:"-" url:"-"`
	Limit                    int          `url:"limit,omitempty"`
	Before                   string       `url:"before,omitempty"`
	After                    string       `url:"after,omitempty"`
	Order                    common.Order `url:"order,omitempty"`
}

// AssignRoleOpts contains the options for assigning a role.
type AssignRoleOpts struct {
	OrganizationMembershipId string             `json:"-"`
	RoleSlug                 string             `json:"role_slug"`
	Resource                 ResourceIdentifier `json:"-"`
}

// RemoveRoleOpts contains the options for removing a role.
type RemoveRoleOpts struct {
	OrganizationMembershipId string             `json:"-"`
	RoleSlug                 string             `json:"role_slug"`
	Resource                 ResourceIdentifier `json:"-"`
}

// RemoveRoleAssignmentOpts contains the options for removing a role assignment by Id.
type RemoveRoleAssignmentOpts struct {
	OrganizationMembershipId string `json:"-"`
	RoleAssignmentId         string `json:"-"`
}

// ListResourcesForMembershipOpts contains the options for listing resources accessible by a membership.
type ListResourcesForMembershipOpts struct {
	OrganizationMembershipId string                   `json:"-" url:"-"`
	PermissionSlug           string                   `url:"permission_slug"`
	ParentResource           ParentResourceIdentifier `json:"-"`
	Limit                    int                      `url:"limit,omitempty"`
	Before                   string                   `url:"before,omitempty"`
	After                    string                   `url:"after,omitempty"`
	Order                    common.Order             `url:"order,omitempty"`
}

// ListMembershipsForResourceOpts contains the options for listing memberships with access to a resource.
type ListMembershipsForResourceOpts struct {
	ResourceId     string       `json:"-" url:"-"`
	PermissionSlug string       `url:"permission_slug"`
	Assignment     string       `url:"assignment,omitempty"`
	Limit          int          `url:"limit,omitempty"`
	Before         string       `url:"before,omitempty"`
	After          string       `url:"after,omitempty"`
	Order          common.Order `url:"order,omitempty"`
}

// ListMembershipsForResourceByExternalIdOpts contains the options for listing memberships by resource external Id.
type ListMembershipsForResourceByExternalIdOpts struct {
	OrganizationId   string       `json:"-" url:"-"`
	ResourceTypeSlug string       `json:"-" url:"-"`
	ExternalId       string       `json:"-" url:"-"`
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
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return EnvironmentRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s", c.Endpoint, authorizationRolesPath)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return EnvironmentRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return EnvironmentRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return EnvironmentRole{}, err
	}

	var body EnvironmentRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListEnvironmentRoles lists all environment roles.
func (c *Client) ListEnvironmentRoles(ctx context.Context) (ListEnvironmentRolesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s", c.Endpoint, authorizationRolesPath)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListEnvironmentRolesResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListEnvironmentRolesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListEnvironmentRolesResponse{}, err
	}

	var body ListEnvironmentRolesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetEnvironmentRole gets an environment role by slug.
func (c *Client) GetEnvironmentRole(ctx context.Context, opts GetEnvironmentRoleOpts) (EnvironmentRole, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationRolesPath, opts.Slug)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return EnvironmentRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return EnvironmentRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return EnvironmentRole{}, err
	}

	var body EnvironmentRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateEnvironmentRole updates an environment role.
func (c *Client) UpdateEnvironmentRole(ctx context.Context, opts UpdateEnvironmentRoleOpts) (EnvironmentRole, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return EnvironmentRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationRolesPath, opts.Slug)
	req, err := http.NewRequest(http.MethodPatch, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return EnvironmentRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return EnvironmentRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return EnvironmentRole{}, err
	}

	var body EnvironmentRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// CreateOrganizationRole creates a new organization role.
func (c *Client) CreateOrganizationRole(ctx context.Context, opts CreateOrganizationRoleOpts) (OrganizationRole, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return OrganizationRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s/roles", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return OrganizationRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationRole{}, err
	}

	var body OrganizationRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListOrganizationRoles lists all roles for an organization.
func (c *Client) ListOrganizationRoles(ctx context.Context, opts ListOrganizationRolesOpts) (ListOrganizationRolesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s/roles", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListOrganizationRolesResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListOrganizationRolesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListOrganizationRolesResponse{}, err
	}

	var body ListOrganizationRolesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetOrganizationRole gets an organization role by slug.
func (c *Client) GetOrganizationRole(ctx context.Context, opts GetOrganizationRoleOpts) (OrganizationRole, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s/roles/%s", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.Slug)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return OrganizationRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationRole{}, err
	}

	var body OrganizationRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateOrganizationRole updates an organization role.
func (c *Client) UpdateOrganizationRole(ctx context.Context, opts UpdateOrganizationRoleOpts) (OrganizationRole, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return OrganizationRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s/roles/%s", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.Slug)
	req, err := http.NewRequest(http.MethodPatch, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return OrganizationRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationRole{}, err
	}

	var body OrganizationRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeleteOrganizationRole deletes an organization role.
func (c *Client) DeleteOrganizationRole(ctx context.Context, opts DeleteOrganizationRoleOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s/roles/%s", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.Slug)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// SetEnvironmentRolePermissions sets permissions for an environment role.
func (c *Client) SetEnvironmentRolePermissions(ctx context.Context, opts SetEnvironmentRolePermissionsOpts) (EnvironmentRole, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return EnvironmentRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s/permissions", c.Endpoint, authorizationRolesPath, opts.Slug)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return EnvironmentRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return EnvironmentRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return EnvironmentRole{}, err
	}

	var body EnvironmentRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// AddEnvironmentRolePermission adds a permission to an environment role.
func (c *Client) AddEnvironmentRolePermission(ctx context.Context, opts AddEnvironmentRolePermissionOpts) (EnvironmentRole, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return EnvironmentRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s/permissions", c.Endpoint, authorizationRolesPath, opts.Slug)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return EnvironmentRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return EnvironmentRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return EnvironmentRole{}, err
	}

	var body EnvironmentRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// SetOrganizationRolePermissions sets permissions for an organization role.
func (c *Client) SetOrganizationRolePermissions(ctx context.Context, opts SetOrganizationRolePermissionsOpts) (OrganizationRole, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return OrganizationRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s/roles/%s/permissions", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.Slug)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return OrganizationRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationRole{}, err
	}

	var body OrganizationRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// AddOrganizationRolePermission adds a permission to an organization role.
func (c *Client) AddOrganizationRolePermission(ctx context.Context, opts AddOrganizationRolePermissionOpts) (OrganizationRole, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return OrganizationRole{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s/roles/%s/permissions", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.Slug)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return OrganizationRole{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationRole{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationRole{}, err
	}

	var body OrganizationRole
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// RemoveOrganizationRolePermission removes a permission from an organization role.
func (c *Client) RemoveOrganizationRolePermission(ctx context.Context, opts RemoveOrganizationRolePermissionOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s/roles/%s/permissions/%s", c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.Slug, opts.PermissionSlug)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// CreatePermission creates a new permission.
func (c *Client) CreatePermission(ctx context.Context, opts CreatePermissionOpts) (Permission, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return Permission{}, err
	}

	endpoint := fmt.Sprintf("%s/%s", c.Endpoint, authorizationPermissionsPath)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return Permission{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Permission{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Permission{}, err
	}

	var body Permission
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListPermissions lists all permissions.
func (c *Client) ListPermissions(ctx context.Context, opts ListPermissionsOpts) (ListPermissionsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s", c.Endpoint, authorizationPermissionsPath)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListPermissionsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = DefaultListSize
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListPermissionsResponse{}, err
	}
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListPermissionsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListPermissionsResponse{}, err
	}

	var body ListPermissionsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetPermission gets a permission by slug.
func (c *Client) GetPermission(ctx context.Context, opts GetPermissionOpts) (Permission, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationPermissionsPath, opts.Slug)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Permission{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Permission{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Permission{}, err
	}

	var body Permission
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdatePermission updates a permission.
func (c *Client) UpdatePermission(ctx context.Context, opts UpdatePermissionOpts) (Permission, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return Permission{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationPermissionsPath, opts.Slug)
	req, err := http.NewRequest(http.MethodPatch, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return Permission{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Permission{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Permission{}, err
	}

	var body Permission
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeletePermission deletes a permission.
func (c *Client) DeletePermission(ctx context.Context, opts DeletePermissionOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationPermissionsPath, opts.Slug)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// GetResource gets a resource by Id.
func (c *Client) GetResource(ctx context.Context, opts GetAuthorizationResourceOpts) (AuthorizationResource, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationResourcesPath, opts.ResourceId)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return AuthorizationResource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthorizationResource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthorizationResource{}, err
	}

	var body AuthorizationResource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// CreateResource creates a new resource.
func (c *Client) CreateResource(ctx context.Context, opts CreateAuthorizationResourceOpts) (AuthorizationResource, error) {
	c.once.Do(c.init)

	// Build request body with optional parent resource identifier.
	bodyMap := map[string]interface{}{
		"external_id":        opts.ExternalId,
		"name":               opts.Name,
		"resource_type_slug": opts.ResourceTypeSlug,
		"organization_id":    opts.OrganizationId,
	}
	if opts.Description != "" {
		bodyMap["description"] = opts.Description
	}
	if opts.Parent != nil {
		for k, v := range opts.Parent.parentResourceIdentifierParams() {
			bodyMap[k] = v
		}
	}

	data, err := c.JSONEncode(bodyMap)
	if err != nil {
		return AuthorizationResource{}, err
	}

	endpoint := fmt.Sprintf("%s/%s", c.Endpoint, authorizationResourcesPath)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return AuthorizationResource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthorizationResource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthorizationResource{}, err
	}

	var body AuthorizationResource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateResource updates a resource.
func (c *Client) UpdateResource(ctx context.Context, opts UpdateAuthorizationResourceOpts) (AuthorizationResource, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return AuthorizationResource{}, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationResourcesPath, opts.ResourceId)
	req, err := http.NewRequest(http.MethodPatch, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return AuthorizationResource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthorizationResource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthorizationResource{}, err
	}

	var body AuthorizationResource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeleteResource deletes a resource.
func (c *Client) DeleteResource(ctx context.Context, opts DeleteAuthorizationResourceOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s/%s", c.Endpoint, authorizationResourcesPath, opts.ResourceId)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.CascadeDelete {
		q := req.URL.Query()
		q.Set("cascade_delete", "true")
		req.URL.RawQuery = q.Encode()
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// ListResources lists resources with optional filters.
func (c *Client) ListResources(ctx context.Context, opts ListAuthorizationResourcesOpts) (ListAuthorizationResourcesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/%s", c.Endpoint, authorizationResourcesPath)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = DefaultListSize
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}

	var body ListAuthorizationResourcesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetResourceByExternalId gets a resource by its external Id.
func (c *Client) GetResourceByExternalId(ctx context.Context, opts GetResourceByExternalIdOpts) (AuthorizationResource, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/%s/%s/resources/%s/%s",
		c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.ResourceTypeSlug, opts.ExternalId,
	)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return AuthorizationResource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthorizationResource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthorizationResource{}, err
	}

	var body AuthorizationResource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateResourceByExternalId updates a resource by its external Id.
func (c *Client) UpdateResourceByExternalId(ctx context.Context, opts UpdateResourceByExternalIdOpts) (AuthorizationResource, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return AuthorizationResource{}, err
	}

	endpoint := fmt.Sprintf(
		"%s/%s/%s/resources/%s/%s",
		c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.ResourceTypeSlug, opts.ExternalId,
	)
	req, err := http.NewRequest(http.MethodPatch, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return AuthorizationResource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthorizationResource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthorizationResource{}, err
	}

	var body AuthorizationResource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeleteResourceByExternalId deletes a resource by its external Id.
func (c *Client) DeleteResourceByExternalId(ctx context.Context, opts DeleteResourceByExternalIdOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/%s/%s/resources/%s/%s",
		c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.ResourceTypeSlug, opts.ExternalId,
	)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.CascadeDelete {
		q := req.URL.Query()
		q.Set("cascade_delete", "true")
		req.URL.RawQuery = q.Encode()
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// Check performs an authorization check.
func (c *Client) Check(ctx context.Context, opts AuthorizationCheckOpts) (AuthorizationCheckResult, error) {
	c.once.Do(c.init)

	// Build request body with resource identifier params.
	bodyMap := map[string]interface{}{
		"permission_slug": opts.PermissionSlug,
	}
	if opts.Resource != nil {
		for k, v := range opts.Resource.resourceIdentifierParams() {
			bodyMap[k] = v
		}
	}

	data, err := c.JSONEncode(bodyMap)
	if err != nil {
		return AuthorizationCheckResult{}, err
	}

	endpoint := fmt.Sprintf(
		"%s/%s/%s/check",
		c.Endpoint, authorizationOrganizationMembershipsPath, opts.OrganizationMembershipId,
	)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return AuthorizationCheckResult{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthorizationCheckResult{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthorizationCheckResult{}, err
	}

	var body AuthorizationCheckResult
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListRoleAssignments lists role assignments for a membership.
func (c *Client) ListRoleAssignments(ctx context.Context, opts ListRoleAssignmentsOpts) (ListRoleAssignmentsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/%s/%s/role_assignments",
		c.Endpoint, authorizationOrganizationMembershipsPath, opts.OrganizationMembershipId,
	)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListRoleAssignmentsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = DefaultListSize
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListRoleAssignmentsResponse{}, err
	}
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListRoleAssignmentsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListRoleAssignmentsResponse{}, err
	}

	var body ListRoleAssignmentsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// AssignRole assigns a role to a membership.
func (c *Client) AssignRole(ctx context.Context, opts AssignRoleOpts) (RoleAssignment, error) {
	c.once.Do(c.init)

	// Build request body with resource identifier params.
	bodyMap := map[string]interface{}{
		"role_slug": opts.RoleSlug,
	}
	if opts.Resource != nil {
		for k, v := range opts.Resource.resourceIdentifierParams() {
			bodyMap[k] = v
		}
	}

	data, err := c.JSONEncode(bodyMap)
	if err != nil {
		return RoleAssignment{}, err
	}

	endpoint := fmt.Sprintf(
		"%s/%s/%s/role_assignments",
		c.Endpoint, authorizationOrganizationMembershipsPath, opts.OrganizationMembershipId,
	)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return RoleAssignment{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return RoleAssignment{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return RoleAssignment{}, err
	}

	var body RoleAssignment
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// RemoveRole removes a role from a membership.
func (c *Client) RemoveRole(ctx context.Context, opts RemoveRoleOpts) error {
	c.once.Do(c.init)

	// Build request body with resource identifier params.
	bodyMap := map[string]interface{}{
		"role_slug": opts.RoleSlug,
	}
	if opts.Resource != nil {
		for k, v := range opts.Resource.resourceIdentifierParams() {
			bodyMap[k] = v
		}
	}

	data, err := c.JSONEncode(bodyMap)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf(
		"%s/%s/%s/role_assignments",
		c.Endpoint, authorizationOrganizationMembershipsPath, opts.OrganizationMembershipId,
	)
	req, err := http.NewRequest(http.MethodDelete, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// RemoveRoleAssignment removes a role assignment by Id.
func (c *Client) RemoveRoleAssignment(ctx context.Context, opts RemoveRoleAssignmentOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/%s/%s/role_assignments/%s",
		c.Endpoint, authorizationOrganizationMembershipsPath, opts.OrganizationMembershipId, opts.RoleAssignmentId,
	)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// ListResourcesForMembership lists resources accessible by a membership.
func (c *Client) ListResourcesForMembership(ctx context.Context, opts ListResourcesForMembershipOpts) (ListAuthorizationResourcesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/%s/%s/resources",
		c.Endpoint, authorizationOrganizationMembershipsPath, opts.OrganizationMembershipId,
	)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = DefaultListSize
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}
	// Add parent resource identifier params if provided.
	if opts.ParentResource != nil {
		for k, v := range opts.ParentResource.parentResourceIdentifierParams() {
			q.Set(k, fmt.Sprintf("%v", v))
		}
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListAuthorizationResourcesResponse{}, err
	}

	var body ListAuthorizationResourcesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListMembershipsForResource lists memberships with access to a resource.
func (c *Client) ListMembershipsForResource(ctx context.Context, opts ListMembershipsForResourceOpts) (ListAuthorizationOrganizationMembershipsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/%s/%s/organization_memberships",
		c.Endpoint, authorizationResourcesPath, opts.ResourceId,
	)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = DefaultListSize
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}

	var body ListAuthorizationOrganizationMembershipsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListMembershipsForResourceByExternalId lists memberships with access to a resource identified by external Id.
func (c *Client) ListMembershipsForResourceByExternalId(ctx context.Context, opts ListMembershipsForResourceByExternalIdOpts) (ListAuthorizationOrganizationMembershipsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/%s/%s/resources/%s/%s/organization_memberships",
		c.Endpoint, authorizationOrganizationsPath, opts.OrganizationId, opts.ResourceTypeSlug, opts.ExternalId,
	)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = DefaultListSize
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListAuthorizationOrganizationMembershipsResponse{}, err
	}

	var body ListAuthorizationOrganizationMembershipsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
