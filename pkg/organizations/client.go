package organizations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v4/pkg/roles"
	"github.com/workos/workos-go/v4/pkg/workos_errors"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v4/internal/workos"
	"github.com/workos/workos-go/v4/pkg/common"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Order represents the order of records.
type Order string

// Constants that enumerate the available orders.
const (
	Asc  Order = "asc"
	Desc Order = "desc"
)

// Client represents a client that performs Organization requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage Organization records from WorkOS.
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

type OrganizationDomainState string

const (
	OrganizationDomainPending        OrganizationDomainState = "pending"
	OrganizationDomainVerified       OrganizationDomainState = "verified"
	OrganizationDomainFailed         OrganizationDomainState = "failed"
	OrganizationDomainLegacyVerified OrganizationDomainState = "legacy_verified"
)

type OrganizationDomainVerificationStrategy string

const (
	Dns    OrganizationDomainVerificationStrategy = "dns"
	Manual OrganizationDomainVerificationStrategy = "manual"
)

// OrganizationDomain contains data about an Organization's Domains.
type OrganizationDomain struct {
	// The Organization Domain's unique identifier.
	ID string `json:"id"`

	// The domain value
	Domain string `json:"domain"`

	// The Organization's unique identifier.
	OrganizationID string `json:"organization_id"`

	// Verification state of the domain.
	State OrganizationDomainState `json:"state"`

	// Strategy used to verify the domain.
	VerificationStrategy OrganizationDomainVerificationStrategy `json:"verification_strategy,omitempty"`

	// Token used for DNS verification.
	VerificationToken string `json:"verification_token,omitempty"`

	// Prefix used for DNS verification.
	VerificationPrefix string `json:"verification_prefix,omitempty"`
}

// Organization contains data about a WorkOS Organization.
type Organization struct {
	// The Organization's unique identifier.
	ID string `json:"id"`

	// The Organization's name.
	Name string `json:"name"`

	// Whether Connections within the Organization allow profiles that are
	// outside of the Organization's configured User Email Domains.
	//
	// Deprecated: If you need to allow sign-ins from any email domain, contact support@workos.com.
	AllowProfilesOutsideOrganization bool `json:"allow_profiles_outside_organization"`

	// The Organization's Domains.
	Domains []OrganizationDomain `json:"domains"`

	// The timestamp of when the Organization was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the Organization was updated.
	UpdatedAt string `json:"updated_at"`

	// The Organization's external id.
	ExternalID string `json:"external_id"`

	// The Organization's metadata.
	Metadata map[string]string `json:"metadata"`
}

// GetOrganizationOpts contains the options to request details for an Organization.
type GetOrganizationOpts struct {
	// Organization unique identifier.
	Organization string
}

type GetOrganizationByExternalIDOpts struct {
	ExternalID string
}

// ListOrganizationsOpts contains the options to request Organizations.
type ListOrganizationsOpts struct {
	// Domains of the Organization.
	Domains []string `url:"domains,brackets,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Organization ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Organization ID.
	After string `url:"after,omitempty"`
}

// ListOrganizationsResponse describes the response structure when requesting
// Organizations
type ListOrganizationsResponse struct {
	// List of provisioned Organizations.
	Data []Organization `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

type OrganizationDomainDataState string

const (
	Verified OrganizationDomainDataState = "verified"
	Pending  OrganizationDomainDataState = "pending"
)

// OrganizationDomainData contains data used to create an OrganizationDomain.
type OrganizationDomainData struct {
	// The domain's value.
	Domain string `json:"domain"`

	// The domain's state.
	State OrganizationDomainDataState `json:"state"`
}

// CreateOrganizationOpts contains the options to create an Organization.
type CreateOrganizationOpts struct {
	// Name of the Organization.
	Name string `json:"name"`

	// Whether Connections within the Organization allow profiles that are
	// outside of the Organization's configured User Email Domains.
	//
	// Deprecated: If you need to allow sign-ins from any email domain, contact support@workos.com.
	AllowProfilesOutsideOrganization bool `json:"allow_profiles_outside_organization"`

	// Domains of the Organization.
	//
	// Deprecated:  Use DomainData instead.
	Domains []string `json:"domains"`

	// Domains of the Organization.
	DomainData []OrganizationDomainData `json:"domain_data"`

	// Optional unique identifier to ensure idempotency
	IdempotencyKey string `json:"idempotency_key,omitempty"`

	// The Organization's external id.
	ExternalID string `json:"external_id"`

	// The Organization's metadata.
	Metadata map[string]string `json:"metadata"`
}

// UpdateOrganizationOpts contains the options to update an Organization.
type UpdateOrganizationOpts struct {
	// Organization unique identifier.
	Organization string

	// Name of the Organization.
	Name string

	// Whether Connections within the Organization allow profiles that are
	// outside of the Organization's configured User Email Domains.
	//
	// Deprecated: If you need to allow sign-ins from any email domain, contact support@workos.com.
	AllowProfilesOutsideOrganization bool

	// Domains of the Organization.
	//
	// Deprecated:  Use DomainData instead.
	Domains []string

	// Domains of the Organization.
	DomainData []OrganizationDomainData `json:"domain_data"`

	// The Organization's external id.
	ExternalID string `json:"external_id"`

	// The Organization's metadata.
	Metadata map[string]string `json:"metadata"`
}

// ListOrganizationsOpts contains the options to request Organizations.
type ListOrganizationRolesOpts struct {
	// The Organization's unique identifier.
	OrganizationID string
}

type ListOrganizationRolesResponse struct {
	// List of roles for the given organization.
	Data []roles.Role `json:"data"`
}

// GetOrganization gets an Organization.
func (c *Client) GetOrganization(
	ctx context.Context,
	opts GetOrganizationOpts,
) (Organization, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/organizations/%s",
		c.Endpoint,
		opts.Organization,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return Organization{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Organization{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Organization{}, err
	}

	var body Organization
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetOrganizationByExternalID gets an Organization by its External ID.
func (c *Client) GetOrganizationByExternalID(
	ctx context.Context,
	opts GetOrganizationByExternalIDOpts,
) (Organization, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/organizations/external_id/%s",
		c.Endpoint,
		opts.ExternalID,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return Organization{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Organization{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Organization{}, err
	}

	var body Organization
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListOrganizations gets a list of WorkOS Organizations.
func (c *Client) ListOrganizations(
	ctx context.Context,
	opts ListOrganizationsOpts,
) (ListOrganizationsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/organizations", c.Endpoint)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListOrganizationsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	if opts.Order == "" {
		opts.Order = Desc
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListOrganizationsResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListOrganizationsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListOrganizationsResponse{}, err
	}

	var body ListOrganizationsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// CreateOrganization creates an Organization.
func (c *Client) CreateOrganization(ctx context.Context, opts CreateOrganizationOpts) (Organization, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return Organization{}, err
	}

	endpoint := fmt.Sprintf("%s/organizations", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return Organization{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Idempotency-Key", opts.IdempotencyKey)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Organization{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Organization{}, err
	}

	var body Organization
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateOrganization updates an Organization.
func (c *Client) UpdateOrganization(ctx context.Context, opts UpdateOrganizationOpts) (Organization, error) {
	c.once.Do(c.init)

	// UpdateOrganizationChangeOpts contains the options to update an Organization minus the org ID
	type UpdateOrganizationChangeOpts struct {
		// Name of the Organization.
		Name string `json:"name"`

		// Whether Connections within the Organization allow profiles that are
		// outside of the Organization's configured User Email Domains.
		AllowProfilesOutsideOrganization bool `json:"allow_profiles_outside_organization"`

		// Domains of the Organization.
		DomainData []OrganizationDomainData `json:"domain_data,omitempty"`

		// Domains of the Organization.
		//
		// Deprecated:  Use DomainData instead.
		Domains []string `json:"domains,omitempty"`
	}

	update_opts := UpdateOrganizationChangeOpts{opts.Name, opts.AllowProfilesOutsideOrganization, opts.DomainData, opts.Domains}

	data, err := c.JSONEncode(update_opts)
	if err != nil {
		return Organization{}, err
	}

	endpoint := fmt.Sprintf("%s/organizations/%s", c.Endpoint, opts.Organization)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return Organization{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Organization{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Organization{}, err
	}

	var body Organization
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeleteOrganizationOpts contains the options to delete an Organization.
type DeleteOrganizationOpts struct {
	// Organization unique identifier.
	Organization string
}

// DeleteOrganization deletes an Organization.
func (c *Client) DeleteOrganization(
	ctx context.Context,
	opts DeleteOrganizationOpts,
) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/Organizations/%s",
		c.Endpoint,
		opts.Organization,
	)
	req, err := http.NewRequest(
		http.MethodDelete,
		endpoint,
		nil,
	)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// ListOrganizationRoles gets a list of roles for the given organization.
func (c *Client) ListOrganizationRoles(
	ctx context.Context,
	opts ListOrganizationRolesOpts,
) (ListOrganizationRolesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/organizations/%s/roles", c.Endpoint, opts.OrganizationID)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListOrganizationRolesResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
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
