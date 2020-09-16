package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/workos-inc/workos-go/internal/workos"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Client represents a client that performs Admin Portal requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage Admin Portal records from WorkOS.
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	once sync.Once
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}
}

// OrganizationDomain contains data about an Organization's Domains.
type OrganizationDomain struct {
	// The Organization Domains's unique identifier.
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

	// The Organization's Domains.
	Domains []OrganizationDomain `json:"domains"`
}

// ListMetadata contains pagination options for organization records.
type ListMetadata struct {
	// Pagination cursor to receive records before a provided ID.
	Before string `json:"before"`

	// Pagination cursor to receive records after a provided ID.
	After string `json:"after"`
}

// ListOrganizationsOpts contains the options to request Organizations.
type ListOrganizationsOpts struct {
	// Domains of the Organization.
	Domains []string

	// Maximum number of records to return.
	Limit int

	// Pagination cursor to receive records before a provided Organization ID.
	Before string

	// Pagination cursor to receive records after a provided Organization ID.
	After string
}

// ListOrganizationsResponse describes the response structure when requesting
// Organizations
type ListOrganizationsResponse struct {
	// List of provisioned Organizations.
	Data []Organization `json:"data"`

	// Cursor pagination options.
	ListMetadata ListMetadata `json:"listMetadata"`
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

	limit := ResponseLimit
	if opts.Limit != 0 {
		limit = opts.Limit
	}
	q := req.URL.Query()

	if len(opts.Domains) > 0 {
		for _, domain := range opts.Domains {
			q.Add("domains", domain)
		}
	}
	q.Add("before", opts.Before)
	q.Add("after", opts.After)
	q.Add("limit", strconv.Itoa(limit))
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListOrganizationsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return ListOrganizationsResponse{}, err
	}

	var body ListOrganizationsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
