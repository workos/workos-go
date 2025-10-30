package widgets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v5/pkg/workos_errors"

	"github.com/workos/workos-go/v5/internal/workos"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Client represents a client that performs Widgets requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage Widgets API calls to WorkOS.
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

// WidgetScope represents a widget token scope.
type WidgetScope string

// Constants that enumerate the available GenerateLinkIntent types.
const (
	UsersTableManage WidgetScope = "widgets:users-table:manage"
)

// GetTokenOpts contains the options to get a widget token.
type GetTokenOpts struct {
	// Organization identifier to scope the widget token
	OrganizationId string `json:"organization_id"`

	// AuthKit user identifier to scope the widget token
	UserId string `json:"user_id"`

	// WidgetScopes to scope the widget token
	Scopes []WidgetScope `json:"scopes"`
}

// GetTokenResponse represents the generated widget token
type GetTokenResponse struct {
	// Generated widget token
	Token string `json:"token"`
}

// GetToken generates a widget token based on the provided options.
func (c *Client) GetToken(
	ctx context.Context,
	opts GetTokenOpts,
) (string, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/widgets/token", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return "", err
	}

	var body GetTokenResponse

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body.Token, err
}
