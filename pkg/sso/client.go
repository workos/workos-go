package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client represents a client that fetch SSO data from WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	APIKey string

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	// The http.Client that is used to send request to WorkOS. Defaults to
	// http.Client.
	HTTPClient *http.Client

	once                     sync.Once
	authorizationURLEndpoint string
	profileEndpoint          string
}

func (c *Client) init() {
	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")
	c.authorizationURLEndpoint = c.Endpoint + "/sso/authorize"
	c.profileEndpoint = c.Endpoint + "/sso/token"

	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: time.Second * 15}
	}
}

// AuthorizationURLOptions contains the options to pass in order to generate
// an authorization url.
type AuthorizationURLOptions struct {
	// The app/company domain without without protocol (eg. example.com).
	Domain string

	// The WorkOS Project ID (eg. project_01JG3BCPTRTSTTWQR4VSHXGWCQ).
	ProjectID string

	// The callback URL where your app redirects the user-agent after an
	// authorization code is granted (eg. https://foo.com/callback).
	RedirectURI string

	// A unique identifier used to manage state across authorization
	// transactions (eg. 1234zyx).
	//
	// Optional.
	State string
}

// AuthorizationURL returns an authorization url generated with the given
// options.
func (c *Client) AuthorizationURL(opts AuthorizationURLOptions) (*url.URL, error) {
	c.once.Do(c.init)

	query := make(url.Values)
	query.Set("domain", opts.Domain)
	query.Set("client_id", opts.ProjectID)
	query.Set("redirect_uri", opts.RedirectURI)
	query.Set("response_type", "code")

	if opts.State != "" {
		query.Set("state", opts.State)
	}

	u, err := url.ParseRequestURI(c.authorizationURLEndpoint)
	if err != nil {
		return nil, err
	}

	u.RawQuery = query.Encode()
	return u, nil
}

// ProfileOptions contains the options to pass in order to get a user profile.
type ProfileOptions struct {
	// An opaque string provided by the authorization server. It will be
	// exchanged for an Access Token when the user’s profile is sent.
	Code string

	// The WorkOS Project ID (eg. project_01JG3BCPTRTSTTWQR4VSHXGWCQ). Must be
	// the one used to generate the authorization url.
	ProjectID string

	// The callback URL where your app redirects the user-agent after an
	// authorization code is granted (eg. https://foo.com/callback). Must be the
	// one used to generate the authorization url.
	RedirectURI string
}

// Profile contains information about a user authentication.
type Profile struct {
	// The user ID.
	ID string

	// An unique alphanumeric identifier for a Profile’s identity provider.
	IdpID string

	// The connection type.
	ConnectionType ConnectionType

	// The user email.
	Email string

	// The user first name. Can be empty.
	FirstName string

	// The user last name. Can be empty.
	LastName string
}

// Profile returns a profile describing the user that authenticated with the
// WorkOS SSO.
func (c *Client) Profile(ctx context.Context, opts ProfileOptions) (Profile, error) {
	c.once.Do(c.init)

	query := make(url.Values)
	query.Set("client_id", opts.ProjectID)
	query.Set("client_secret", c.APIKey)
	query.Set("redirect_uri", opts.RedirectURI)
	query.Set("grant_type", "authorization_code")
	query.Set("code", opts.Code)

	req, err := http.NewRequest(
		http.MethodPost,
		c.profileEndpoint,
		strings.NewReader(query.Encode()),
	)
	if err != nil {
		return Profile{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "workos-go/"+version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Profile{}, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return Profile{}, errors.New(res.Status)
	}

	var profile Profile
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&profile)
	return profile, err
}