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

type AuthorizationURLOptions struct {
	Domain      string
	ProjectID   string
	RedirectURI string
	State       string
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

type ProfileOptions struct {
	Code        string
	ProjectID   string
	RedirectURI string
}

type Profile struct {
	ID             string
	IdpID          string
	ConnectionType ConnectionType
	Email          string
	FirstName      string
	LastName       string
}

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
