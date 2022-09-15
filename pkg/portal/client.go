package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/pkg/workos_errors"

	"github.com/workos/workos-go/internal/workos"
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

// Client represents a client that performs Admin Portal requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage Admin Portal records from WorkOS.
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

// GenerateLinkIntent represents the intent of an Admin Portal.
type GenerateLinkIntent string

// Constants that enumerate the available GenerateLinkIntent types.
const (
	SSO       GenerateLinkIntent = "sso"
	DSync     GenerateLinkIntent = "dsync"
	AuditLogs GenerateLinkIntent = "audit_logs"
)

// GenerateLinkOpts contains the options to request Organizations.
type GenerateLinkOpts struct {
	// Intent of the Admin Portal
	Intent GenerateLinkIntent `json:"intent"`

	// Organization identifier to scope the Portal Session
	Organization string `json:"organization"`

	// The URL to which users will return to when finished with the Admin Portal.
	ReturnURL string `json:"return_url"`
}

// generatedLinkResponse represents the generated Portal Link
type generateLinkResponse struct {
	// Generated Portal Link
	Link string `json:"link"`
}

// GenerateLink generates a link to the Admin Portal
func (c *Client) GenerateLink(
	ctx context.Context,
	opts GenerateLinkOpts,
) (string, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/portal/generate_link", c.Endpoint)
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

	var body generateLinkResponse

	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body.Link, err
}
