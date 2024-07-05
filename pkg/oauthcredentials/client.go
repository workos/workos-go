package oauthcredentials

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/v4/pkg/workos_errors"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v4/internal/workos"
	"github.com/workos/workos-go/v4/pkg/common"
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

// Client represents a client that performs OAuthCredential requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to manage OAuthCredential records from WorkOS.
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

// OAuthConnectionType represents the type of OAuth Connection.
type OAuthConnectionType string

// Constants that enumerate the available oauth connection types.
const (
	AppleOauth     OAuthConnectionType = "AppleOauth"
	GithubOauth    OAuthConnectionType = "GitHubOauth"
	GoogleOauth    OAuthConnectionType = "GoogleOauth"
	MicrosoftOauth OAuthConnectionType = "MicrosoftOauth"
)

// OAuthConnectionState represents the state of an OAuth Connection.
type OAuthConnectionState string

// Constants that enumerate the available oauth connection states.
const (
	Valid   OAuthConnectionState = "Valid"
	Invalid OAuthConnectionState = "Invalid"
)

// OAuthCredential contains data about a WorkOS OauthCredential Auth Method.
type OAuthCredential struct {
	// The OauthCredential's unique identifier.
	ID string `json:"id"`

	// The OauthCredential's type.
	Type OAuthConnectionType `json:"type"`

	// The OauthCredential's state.
	State OAuthConnectionState `json:"state"`

	// The OauthCredential's external key.
	ExternalKey string `json:"externalKey"`

	// The OauthCredential's client ID.
	ClientID string `json:"clientId"`

	// The OauthCredential's client secret.
	ClientSecret string `json:"clientSecret"`

	// The OauthCredential's redirect URI.
	RedirectURI string `json:"redirectUri"`

	// The OauthCredential's userland enabled state.
	IsUserlandEnabled bool `json:"isUserlandEnabled"`

	// The OauthCredential's Apple Team ID.
	AppleTeamID string `json:"appleTeamId"`

	// The OauthCredential's Apple Key ID.
	AppleKeyID string `json:"appleKeyId"`

	// The OauthCredential's Apple Private Key.
	ApplePrivateKey string `json:"applePrivateKey"`

	// The timestamp of when the OAuthCredential was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the OAuthCredential was updated.
	UpdatedAt string `json:"updated_at"`
}

// GetOAuthCredentialOpts contains the options to request details for an OAuthCredential.
type GetOAuthCredentialOpts struct {
	// Oauth Credential unique identifier.
	ID string
}

// ListOAuthCredentialsOpts contains the options to request OAuthCredentials.
type ListOAuthCredentialsOpts struct {
	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided OAuthCredential ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided OAuthCredential ID.
	After string `url:"after,omitempty"`
}

// ListOAuthCredentialsResponse describes the response structure when requesting
// OAuthCredentials
type ListOAuthCredentialsResponse struct {
	// List of provisioned OAuthCredentials.
	Data []OAuthCredential `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// UpdateOAuthCredentialOpts contains the options to update an OAuthCredential.
type UpdateOAuthCredentialOpts struct {
	// OAuthCredential unique identifier.
	ID string

	// The OauthCredential's client ID.
	ClientID string `json:"clientId"`

	// The OauthCredential's client secret.
	ClientSecret string `json:"clientSecret"`

	// The OauthCredential's redirect URI.
	RedirectURI string `json:"redirectUri"`

	// The OauthCredential's userland enabled state.
	IsUserlandEnabled bool `json:"isUserlandEnabled"`

	// The OauthCredential's Apple Team ID.
	AppleTeamID string `json:"appleTeamId"`

	// The OauthCredential's Apple Key ID.
	AppleKeyID string `json:"appleKeyId"`

	// The OauthCredential's Apple Private Key.
	ApplePrivateKey string `json:"applePrivateKey"`
}

// GetOAuthCredential gets an OAuthCredential.
func (c *Client) GetOAuthCredential(
	ctx context.Context,
	opts GetOAuthCredentialOpts,
) (OAuthCredential, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/oauth-credentials/%s",
		c.Endpoint,
		opts.ID,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return OAuthCredential{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OAuthCredential{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OAuthCredential{}, err
	}

	var body OAuthCredential
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListOAuthCredentials gets a list of WorkOS OAuthCredentials.
func (c *Client) ListOAuthCredentials(
	ctx context.Context,
	opts ListOAuthCredentialsOpts,
) (ListOAuthCredentialsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/oauth-credentials", c.Endpoint)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListOAuthCredentialsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	if opts.Order == "" {
		opts.Order = Desc
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListOAuthCredentialsResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListOAuthCredentialsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListOAuthCredentialsResponse{}, err
	}

	var body ListOAuthCredentialsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateOAuthCredential updates an OAuthCredential.
func (c *Client) UpdateOAuthCredential(ctx context.Context, opts UpdateOAuthCredentialOpts) (OAuthCredential, error) {
	c.once.Do(c.init)

	// UpdateOAuthCredentialChangeOpts contains the options to update an OAuthCredential minus the org ID
	type UpdateOAuthCredentialChangeOpts struct {
		// The OauthCredential's client ID.
		ClientID string `json:"clientId"`

		// The OauthCredential's client secret.
		ClientSecret string `json:"clientSecret"`

		// The OauthCredential's redirect URI.
		RedirectURI string `json:"redirectUri"`

		// The OauthCredential's userland enabled state.
		IsUserlandEnabled bool `json:"isUserlandEnabled"`

		// The OauthCredential's Apple Team ID.
		AppleTeamID string `json:"appleTeamId"`

		// The OauthCredential's Apple Key ID.
		AppleKeyID string `json:"appleKeyId"`

		// The OauthCredential's Apple Private Key.
		ApplePrivateKey string `json:"applePrivateKey"`
	}

	update_opts := UpdateOAuthCredentialChangeOpts{
		opts.ClientID,
		opts.ClientSecret,
		opts.RedirectURI,
		opts.IsUserlandEnabled,
		opts.AppleTeamID,
		opts.AppleKeyID,
		opts.ApplePrivateKey,
	}

	data, err := c.JSONEncode(update_opts)
	if err != nil {
		return OAuthCredential{}, err
	}

	endpoint := fmt.Sprintf("%s/organizations/%s", c.Endpoint, opts.ID)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return OAuthCredential{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OAuthCredential{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OAuthCredential{}, err
	}

	var body OAuthCredential
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

type CreateOAuthCredentialOpts struct {
	Type OAuthConnectionType `json:"type"`
}

func (c *Client) CreateOAuthCredential(ctx context.Context, opts CreateOAuthCredentialOpts) (OAuthCredential, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return OAuthCredential{}, err
	}

	endpoint := fmt.Sprintf("%s/oauth-credentials", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return OAuthCredential{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OAuthCredential{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OAuthCredential{}, err
	}

	var body OAuthCredential
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
