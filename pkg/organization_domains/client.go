package organization_domains

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v4/internal/workos"
	"github.com/workos/workos-go/v4/pkg/workos_errors"
)

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

// GetOrganizationDomainOpts contains the options to get a domain.
type GetOrganizationDomainOpts struct {
	DomainID string
}

// CreateOrganizationDomainOpts contains the options to create a domain.
type CreateOrganizationDomainOpts struct {
	OrganizationID string `json:"organization_id"`
	Domain         string `json:"domain"`
}

// VerifyOrganizationDomainOpts contains the options to verify a domain.
type VerifyOrganizationDomainOpts struct {
	DomainID string
}

// DeleteOrganizationDomainOpts contains the options to delete a domain.
type DeleteOrganizationDomainOpts struct {
	DomainID string
}

// Client represents a client that performs Organization Domain requests to the WorkOS API.
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

// GetDomain gets an Organization Domain.
func (c *Client) GetDomain(ctx context.Context, opts GetOrganizationDomainOpts) (OrganizationDomain, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/organization_domains/%s",
		c.Endpoint,
		opts.DomainID,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return OrganizationDomain{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationDomain{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationDomain{}, err
	}

	var body OrganizationDomain
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// CreateDomain creates an Organization Domain.
func (c *Client) CreateDomain(ctx context.Context, opts CreateOrganizationDomainOpts) (OrganizationDomain, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return OrganizationDomain{}, err
	}

	endpoint := fmt.Sprintf("%s/organization_domains", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return OrganizationDomain{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationDomain{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationDomain{}, err
	}

	var body OrganizationDomain
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// VerifyDomain verifies an Organization Domain.
func (c *Client) VerifyDomain(ctx context.Context, opts VerifyOrganizationDomainOpts) (OrganizationDomain, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/organization_domains/%s/verify", c.Endpoint, opts.DomainID)
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return OrganizationDomain{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationDomain{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationDomain{}, err
	}

	var body OrganizationDomain
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeleteDomain deletes an Organization Domain.
func (c *Client) DeleteDomain(ctx context.Context, opts DeleteOrganizationDomainOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/organization_domains/%s",
		c.Endpoint,
		opts.DomainID,
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

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return err
	}

	return nil
}
