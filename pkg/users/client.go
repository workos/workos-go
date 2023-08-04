package users

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
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

// Client represents a client that fetch SSO data from WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	//
	// REQUIRED.
	APIKey string

	// The WorkOS Client ID (eg. client_01JG3BCPTRTSTTWQR4VSHXGWCQ).
	//
	// REQUIRED.
	ClientID string

	// The endpoint to WorkOS API.
	//
	// Defaults to https://api.workos.com.
	Endpoint string

	// The http.Client that is used to send request to WorkOS.
	//
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")

	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: time.Second * 15}
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}
