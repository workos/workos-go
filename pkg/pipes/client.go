package pipes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v6/internal/workos"
	"github.com/workos/workos-go/v6/pkg/workos_errors"
)

// GetAccessTokenError represents the error type when an access token cannot be retrieved.
type GetAccessTokenError string

// Constants that enumerate the available access token errors.
const (
	NotInstalled         GetAccessTokenError = "not_installed"
	NeedsReauthorization GetAccessTokenError = "needs_reauthorization"
)

// Client represents a client that performs Pipes requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage Pipes requests to WorkOS.
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

// AccessToken contains data about an OAuth access token for a data integration.
type AccessToken struct {
	// The object type identifier.
	Object string `json:"object"`

	// The OAuth access token value.
	AccessToken string `json:"access_token"`

	// The timestamp when the access token expires, or nil if it doesn't expire.
	ExpiresAt *time.Time `json:"expires_at"`

	// The scopes that have been granted for this access token.
	Scopes []string `json:"scopes"`

	// The scopes that were requested but have not been granted.
	MissingScopes []string `json:"missing_scopes"`
}

// GetAccessTokenOpts contains the options to request an access token.
type GetAccessTokenOpts struct {
	// Provider is the data provider identifier (e.g., "salesforce").
	Provider string `json:"-"`

	// UserID is the ID of the user requesting the token.
	UserID string `json:"user_id"`

	// OrganizationID is the optional organization context for the token.
	OrganizationID string `json:"organization_id,omitempty"`
}

// GetAccessTokenResponse represents the response from requesting an access token.
// When Active is true, AccessToken will contain the token details.
// When Active is false, Error will contain the reason why the token could not be retrieved.
type GetAccessTokenResponse struct {
	// Active indicates whether the token request was successful.
	Active bool `json:"active"`

	// AccessToken contains the token details when Active is true.
	AccessToken *AccessToken `json:"access_token,omitempty"`

	// Error contains the error type when Active is false.
	Error GetAccessTokenError `json:"error,omitempty"`
}

// GetAccessToken retrieves an OAuth access token for a third-party data provider
// on behalf of a user.
func (c *Client) GetAccessToken(
	ctx context.Context,
	opts GetAccessTokenOpts,
) (GetAccessTokenResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return GetAccessTokenResponse{}, err
	}

	endpoint := fmt.Sprintf(
		"%s/data-integrations/%s/token",
		c.Endpoint,
		opts.Provider,
	)
	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return GetAccessTokenResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return GetAccessTokenResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return GetAccessTokenResponse{}, err
	}

	var body GetAccessTokenResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
