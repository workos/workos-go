package roles

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v4/pkg/workos_errors"

	"github.com/workos/workos-go/v4/internal/workos"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Client represents a client that performs Roles requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage Roles API calls to WorkOS.
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

// RoleType represents the type of a Role.
type RoleType string

// Constants that enumerate the type of a Role.
const (
	Environment  RoleType = "EnvironmentRole"
	Organization RoleType = "OrganizationRole"
)

// Role contains data about a WorkOS Role.
type Role struct {
	// The Role's unique identifier.
	ID string `json:"id"`

	Name string `json:"name"`

	// The Role's slug key for referencing it in code.
	Slug string `json:"slug"`

	Description string `json:"description"`

	// The type of role
	Type RoleType `json:"type"`

	// The timestamp of when the Role was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the Role was updated.
	UpdatedAt string `json:"updated_at"`
}

// ListRolesOpts contains the options to request Roles.
type ListRolesOpts struct{}

// ListRolesResponse describes the response structure when requesting Roles.
type ListRolesResponse struct {
	// List of provisioned Roles.
	Data []Role `json:"data"`
}

// ListRoles lists all roles in a WorkOS environment.
func (c *Client) ListRoles(
	ctx context.Context,
	opts ListRolesOpts,
) (ListRolesResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return ListRolesResponse{}, err
	}

	endpoint := fmt.Sprintf("%s/roles", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return ListRolesResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListRolesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListRolesResponse{}, err
	}

	var body ListRolesResponse

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
