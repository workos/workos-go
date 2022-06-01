package organizations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/pkg/workos_errors"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/internal/workos"
	"github.com/workos/workos-go/pkg/common"
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

// OrganizationDomain contains data about an Organization's Domains.
type OrganizationDomain struct {
	// The Organization Domain's unique identifier.
	ID string `json:"id"`

	// The domain value
	Domain string `json:"domain"`
}

// Organization contains data about a WorkOS Organization.
type Organization struct {
	// The Organization's unique identifier.
	ID string `json:"id"`

	// The Organization's name.
	Name string `json:"name"`

	// Whether Connections within the Organization allow profiles that are
	// outside of the Organization's configured User Email Domains.
	AllowProfilesOutsideOrganization bool `json:"allow_profiles_outside_organization"`

	// The Organization's Domains.
	Domains []OrganizationDomain `json:"domains"`

	// The timestamp of when the Organization was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the Organization was updated.
	UpdatedAt string `json:"updated_at"`
}

// GetOrganizationOpts contains the options to request details for an Organization.
type GetOrganizationOpts struct {
	// Organization unique identifier.
	Organization string
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

// CreateOrganizationOpts contains the options to create an Organization.
type CreateOrganizationOpts struct {
	// Name of the Organization.
	Name string `json:"name"`

	// Whether Connections within the Organization allow profiles that are
	// outside of the Organization's configured User Email Domains.
	AllowProfilesOutsideOrganization bool `json:"allow_profiles_outside_organization"`

	// Domains of the Organization.
	Domains []string `json:"domains"`
}

// UpdateOrganizationOpts contains the options to update an Organization.
type UpdateOrganizationOpts struct {
	// Organization unique identifier.
	Organization string

	// Name of the Organization.
	Name string

	// Whether Connections within the Organization allow profiles that are
	// outside of the Organization's configured User Email Domains.
	AllowProfilesOutsideOrganization bool

	// Domains of the Organization.
	Domains []string
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
		Domains []string `json:"domains"`
	}

	update_opts := UpdateOrganizationChangeOpts{opts.Name, opts.AllowProfilesOutsideOrganization, opts.Domains}

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
