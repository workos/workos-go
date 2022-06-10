package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/workos/workos-go/pkg/workos_errors"

	"github.com/workos/workos-go/internal/workos"
	"github.com/workos/workos-go/pkg/common"
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

// ConnectionType represents a connection type.
type ConnectionType string

// Constants that enumerate the available connection types.
const (
	ADFSSAML          ConnectionType = "ADFSSAML"
	AdpOidc           ConnectionType = "AdpOidc"
	Auth0SAML         ConnectionType = "Auth0SAML"
	AzureSAML         ConnectionType = "AzureSAML"
	CasSAML           ConnectionType = "CasSAML"
	CloudflareSAML    ConnectionType = "CloudflareSAML"
	ClassLinkSAML     ConnectionType = "ClassLinkSAML"
	CyberArkSAML      ConnectionType = "CyberArkSAML"
	DuoSAML           ConnectionType = "DuoSAML"
	GenericOIDC       ConnectionType = "GenericOIDC"
	GenericSAML       ConnectionType = "GenericSAML"
	GoogleOAuth       ConnectionType = "GoogleOAuth"
	GoogleSAML        ConnectionType = "GoogleSAML"
	JumpCloudSAML     ConnectionType = "JumpCloudSAML"
	MagicLink         ConnectionType = "MagicLink"
	MicrosoftOAuth    ConnectionType = "MicrosoftOAuth"
	MiniOrangeSAML    ConnectionType = "MiniOrangeSAML"
	NetIqSAML         ConnectionType = "NetIqSAML"
	OktaSAML          ConnectionType = "OktaSAML"
	OneLoginSAML      ConnectionType = "OneLoginSAML"
	OracleSAML        ConnectionType = "OracleSAML"
	PingFederateSAML  ConnectionType = "PingFederateSAML"
	PingOneSAML       ConnectionType = "PingOneSAML"
	RipplingSAML      ConnectionType = "RipplingSAML"
	SalesforceSAML    ConnectionType = "SalesforceSAML"
	ShibbolethSAML    ConnectionType = "ShibbolethSAML"
	SimpleSamlPhpSAML ConnectionType = "SimpleSamlPhpSAML"
	VMwareSAML        ConnectionType = "VMwareSAML"
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

// GetAuthorizationURLOptions contains the options to pass in order to generate
// an authorization url.
type GetAuthorizationURLOptions struct {
	// Deprecated: Please use `Organization` parameter instead.
	// The app/company domain without without protocol (eg. example.com).
	Domain string

	// Domain hint that will be passed as a parameter to the IdP login page.
	// OPTIONAL.
	DomainHint string

	// Username/email hint that will be passed as a parameter to the to IdP login page.
	// OPTIONAL.
	LoginHint string

	// Authentication service provider descriptor.
	// Provider is currently only used when the connection type is GoogleOAuth.
	Provider ConnectionType

	// The unique identifier for a WorkOS Connection.
	Connection string

	// The unique identifier for a WorkOS Organization.
	Organization string

	// The callback URL where your app redirects the user-agent after an
	// authorization code is granted (eg. https://foo.com/callback).
	//
	// REQUIRED.
	RedirectURI string

	// A unique identifier used to manage state across authorization
	// transactions (eg. 1234zyx).
	//
	// OPTIONAL.
	State string
}

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func (c *Client) GetAuthorizationURL(opts GetAuthorizationURLOptions) (*url.URL, error) {
	c.once.Do(c.init)

	redirectURI := opts.RedirectURI

	query := make(url.Values, 5)
	query.Set("client_id", c.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")

	if opts.Domain == "" && opts.Provider == "" && opts.Connection == "" && opts.Organization == "" {
		return nil, errors.New("incomplete arguments: missing connection, organization, domain, or provider")
	}
	if opts.Provider != "" {
		query.Set("provider", string(opts.Provider))
	}
	if opts.Domain != "" {
		query.Set("domain", opts.Domain)
		fmt.Println("The `domain` parameter for `getAuthorizationURL` is deprecated. Please use `organization` instead.")
	}
	if opts.DomainHint != "" {
		query.Set("domain_hint", opts.DomainHint)
	}
	if opts.LoginHint != "" {
		query.Set("login_hint", opts.LoginHint)
	}
	if opts.Connection != "" {
		query.Set("connection", opts.Connection)
	}

	if opts.Organization != "" {
		query.Set("organization", opts.Organization)
	}

	if opts.State != "" {
		query.Set("state", opts.State)
	}

	u, err := url.ParseRequestURI(c.Endpoint + "/sso/authorize")
	if err != nil {
		return nil, err
	}

	u.RawQuery = query.Encode()
	return u, nil
}

// GetProfileAndTokenOptions contains the options to pass in order to get a user profile and access token.
type GetProfileAndTokenOptions struct {
	// An opaque string provided by the authorization server. It will be
	// exchanged for an Access Token when the user’s profile is sent.
	Code string
}

// Profile contains information about an authenticated user.
type Profile struct {
	// The user ID.
	ID string `json:"id"`

	// An unique alphanumeric identifier for a Profile’s identity provider.
	IdpID string `json:"idp_id"`

	// The organization ID.
	OrganizationID string `json:"organization_id"`

	// The connection ID.
	ConnectionID string `json:"connection_id"`

	// The connection type.
	ConnectionType ConnectionType `json:"connection_type"`

	// The user email.
	Email string `json:"email"`

	// The user first name. Can be empty.
	FirstName string `json:"first_name"`

	// The user last name. Can be empty.
	LastName string `json:"last_name"`

	// The raw response of Profile attributes from the identity provider
	RawAttributes map[string]interface{} `json:"raw_attributes"`
}

type ProfileAndToken struct {
	// An access token corresponding to the Profile.
	AccessToken string `json:"access_token"`

	// The user Profile.
	Profile Profile `json:"profile"`
}

// GetProfileAndToken returns a profile describing the user that authenticated with
// WorkOS SSO.
func (c *Client) GetProfileAndToken(ctx context.Context, opts GetProfileAndTokenOptions) (ProfileAndToken, error) {
	c.once.Do(c.init)

	form := make(url.Values, 5)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.APIKey)
	form.Set("grant_type", "authorization_code")
	form.Set("code", opts.Code)

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/sso/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return ProfileAndToken{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ProfileAndToken{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ProfileAndToken{}, err
	}

	var body ProfileAndToken
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// GetProfile contains the options to pass in order to get a user profile.
type GetProfileOptions struct {
	// An opaque string provided by the authorization server. It will be
	// exchanged for an Access Token when the user’s profile is sent.
	AccessToken string
}

// GetProfile returns a profile describing the user that authenticated with
// WorkOS SSO.
func (c *Client) GetProfile(ctx context.Context, opts GetProfileOptions) (Profile, error) {
	c.once.Do(c.init)

	req, err := http.NewRequest(
		http.MethodGet,
		c.Endpoint+"/sso/profile",
		nil,
	)
	if err != nil {
		return Profile{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+opts.AccessToken)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Profile{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Profile{}, err
	}

	var body Profile
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// ConnectionDomain represents the domain records associated with a Connection.
type ConnectionDomain struct {
	// Connection Domain unique identifier.
	ID string `json:"id"`

	// Domain for a Connection record.
	Domain string `json:"domain"`
}

// ConnectionStatus represents a Connection's linked status.
//
// Deprecated: Please use ConnectionState instead.
type ConnectionStatus string

// Constants that enumerate the available Connection's linked statuses.
const (
	Linked   ConnectionStatus = "linked"
	Unlinked ConnectionStatus = "unlinked"
)

// ConnectionState indicates whether a Connection is able to authenticate users.
type ConnectionState string

// Constants that enumerate a Connection's possible states.
const (
	Draft    ConnectionState = "draft"
	Active   ConnectionState = "active"
	Inactive ConnectionState = "inactive"
)

// Connection represents a Connection record.
type Connection struct {
	// Connection unique identifier.
	ID string `json:"id"`

	// Connection linked status. Deprecated; use State instead.
	Status ConnectionStatus `json:"status"`

	// Connection linked state.
	State ConnectionState `json:"state"`

	// Connection name.
	Name string `json:"name"`

	// Connection provider type.
	ConnectionType ConnectionType `json:"connection_type"`

	// Organization ID.
	OrganizationID string `json:"organization_id"`

	// Domain records for the Connection.
	Domains []ConnectionDomain `json:"domains"`

	// The timestamp of when the Connection was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the Connection was updated.
	UpdatedAt string `json:"updated_at"`
}

// GetConnectionOpts contains the options to request details for a Connection.
type GetConnectionOpts struct {
	// Connection unique identifier.
	Connection string
}

// GetConnection gets a Connection.
func (c *Client) GetConnection(
	ctx context.Context,
	opts GetConnectionOpts,
) (Connection, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/connections/%s",
		c.Endpoint,
		opts.Connection,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return Connection{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Connection{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Connection{}, err
	}

	var body Connection
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListConnectionsOpts contains the options to request a list of Connections.
type ListConnectionsOpts struct {
	// Authentication service provider descriptor. Can be empty.
	ConnectionType ConnectionType

	// Organization ID of the Connection(s). Can be empty.
	OrganizationID string

	// Domain of a Connection. Can be empty.
	Domain string

	// Maximum number of records to return.
	Limit int

	// The order in which to paginate records.
	Order Order

	// Pagination cursor to receive records before a provided Connection ID.
	Before string

	// Pagination cursor to receive records after a provided Connection ID.
	After string
}

// ListConnectionsResponse describes the response structure when requesting
// existing Connections.
type ListConnectionsResponse struct {
	// List of Connections
	Data []Connection `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// ListConnections gets details of existing Connections.
func (c *Client) ListConnections(
	ctx context.Context,
	opts ListConnectionsOpts,
) (ListConnectionsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/connections", c.Endpoint)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListConnectionsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	limit := ResponseLimit
	if opts.Limit != 0 {
		limit = opts.Limit
	}
	q := req.URL.Query()
	q.Add("before", opts.Before)
	q.Add("after", opts.After)
	if opts.ConnectionType != "" {
		q.Add("connection_type", string(opts.ConnectionType))
	}
	q.Add("organization_id", string(opts.OrganizationID))
	q.Add("domain", opts.Domain)
	q.Add("limit", strconv.Itoa(limit))
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListConnectionsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListConnectionsResponse{}, err
	}

	var body ListConnectionsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeleteConnectionOpts contains the options to delete a Connection.
type DeleteConnectionOpts struct {
	// Connection unique identifier.
	Connection string
}

// DeleteConnection deletes a Connection.
func (c *Client) DeleteConnection(
	ctx context.Context,
	opts DeleteConnectionOpts,
) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/connections/%s",
		c.Endpoint,
		opts.Connection,
	)
	req, err := http.NewRequest(
		http.MethodDelete,
		endpoint,
		nil,
	)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}
