package passwordless

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

// Client represents a client that performs Passwordless requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key.
	// It can be found in https://dashboard.workos.com/api-keys.
	//
	// REQUIRED
	APIKey string

	// The http.Client that is used to send request to WorkOS.
	//
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API.
	//
	// Defaults to https://api.workos.com.
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

// PasswordlessSession contains data about a WorkOS Passwordless Session.
type PasswordlessSession struct {
	// The Passwordless Session's unique identifier.
	ID string `json:"id"`

	// The email of the user to authenticate.
	Email string `json:"email"`

	// ISO-8601 datetime at which the Passwordless Session link expires.
	ExpiresAt string `json:"expires_at"`

	// The link for the user to authenticate with.
	Link string `json:"link"`
}

// CreateSessionType represents the type of a Passwordless Session.
type PasswordlessSessionType string

// Constants that enumerate the available PasswordlessSessionType values.
const (
	MagicLink PasswordlessSessionType = "MagicLink"
)

// CreateSessionOpts contains the options to create a Passowordless Session.
type CreateSessionOpts struct {
	// The email of the user to authenticate.
	//
	// REQUIRED
	Email string `json:"email"`

	// The type of Passwordless Session to create.
	//
	// REQUIRED
	Type PasswordlessSessionType `json:"type"`

	// Optional The unique identifier for a WorkOS Connection.
	Connection string `json:"connection"`

	// Optional string value used to set the location
	// that the user will be redirected to after authenticating
	RedirectURI string `json:"redirect_uri"`

	// Optional string value used to manage application state
	// between authorization transactions.
	State string `json:"state"`

	// Optional The number of seconds the Passwordless Session
	// should live before expiring.
	ExpiresIn int `json:"expires_in"`
}

// CreateSession creates a a PasswordlessSession.
func (c *Client) CreateSession(ctx context.Context, opts CreateSessionOpts) (PasswordlessSession, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return PasswordlessSession{}, err
	}

	endpoint := fmt.Sprintf("%s/passwordless/sessions", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return PasswordlessSession{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return PasswordlessSession{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return PasswordlessSession{}, err
	}

	var body PasswordlessSession
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// SendSessionOpts contains the options to send a Passwordless Session via email.
type SendSessionOpts struct {
	// Passwordless Session unique identifier.
	ID string
}

// SendSession sends a Passwordless Session via email
func (c *Client) SendSession(
	ctx context.Context,
	opts SendSessionOpts,
) error {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf(
		"%s/passwordless/sessions/%s/send",
		c.Endpoint,
		opts.ID,
	)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}
