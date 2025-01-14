package permissions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v4/pkg/common"
	"github.com/workos/workos-go/v4/pkg/workos_errors"

	"github.com/workos/workos-go/v4/internal/workos"
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

// Client represents a client that performs Permissions requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage Permissions API calls to WorkOS.
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

// Permission contains data about a WorkOS Permission.
type Permission struct {
	// The Permission's unique identifier.
	ID string `json:"id"`

	Name string `json:"name"`

	// The Permission's slug key for referencing it in code.
	Slug string `json:"slug"`

	Description string `json:"description"`

	// Whether this Permission is a system permission.
	System bool `json:"system"`

	// The timestamp of when the Permission was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the Permission was updated.
	UpdatedAt string `json:"updated_at"`
}

// ListPermissionsOpts contains the options to request Permissions.
type ListPermissionsOpts struct {
	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Organization ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Organization ID.
	After string `url:"after,omitempty"`
}

// ListPermissionsResponse describes the response structure when requesting Permissions
type ListPermissionsResponse struct {
	// List of provisioned Permissions.
	Data []Permission `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// ListPermissions lists all permissions in a WorkOS environment.
func (c *Client) ListPermissions(
	ctx context.Context,
	opts ListPermissionsOpts,
) (ListPermissionsResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return ListPermissionsResponse{}, err
	}

	endpoint := fmt.Sprintf("%s/permissions", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return ListPermissionsResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

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
