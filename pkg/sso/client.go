package sso

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/workos/workos-go/v2/pkg/workos_errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/workos/workos-go/v2/internal/workos"
	"github.com/workos/workos-go/v2/pkg/common"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// ConnectionType represents a connection type.
type ConnectionType string

// Constants that enumerate the available connection types.
const (
	ADFSSAML              ConnectionType = "ADFSSAML"
	AdpOidc               ConnectionType = "AdpOidc"
	Auth0SAML             ConnectionType = "Auth0SAML"
	AzureSAML             ConnectionType = "AzureSAML"
	CasSAML               ConnectionType = "CasSAML"
	CloudflareSAML        ConnectionType = "CloudflareSAML"
	ClassLinkSAML         ConnectionType = "ClassLinkSAML"
	CyberArkSAML          ConnectionType = "CyberArkSAML"
	DuoSAML               ConnectionType = "DuoSAML"
	GenericOIDC           ConnectionType = "GenericOIDC"
	GenericSAML           ConnectionType = "GenericSAML"
	GoogleOAuth           ConnectionType = "GoogleOAuth"
	GoogleSAML            ConnectionType = "GoogleSAML"
	JumpCloudSAML         ConnectionType = "JumpCloudSAML"
	KeycloakSAML          ConnectionType = "KeycloakSAML"
	LastPassSAML          ConnectionType = "LastPassSAML"
	LoginGovOidc          ConnectionType = "LoginGovOidc"
	MagicLink             ConnectionType = "MagicLink"
	MicrosoftOAuth        ConnectionType = "MicrosoftOAuth"
	MiniOrangeSAML        ConnectionType = "MiniOrangeSAML"
	NetIqSAML             ConnectionType = "NetIqSAML"
	OktaSAML              ConnectionType = "OktaSAML"
	OneLoginSAML          ConnectionType = "OneLoginSAML"
	OracleSAML            ConnectionType = "OracleSAML"
	PingFederateSAML      ConnectionType = "PingFederateSAML"
	PingOneSAML           ConnectionType = "PingOneSAML"
	RipplingSAML          ConnectionType = "RipplingSAML"
	SalesforceSAML        ConnectionType = "SalesforceSAML"
	ShibbolethSAML        ConnectionType = "ShibbolethSAML"
	ShibbolethGenericSAML ConnectionType = "ShibbolethGenericSAML"
	SimpleSamlPhpSAML     ConnectionType = "SimpleSamlPhpSAML"
	VMwareSAML            ConnectionType = "VMwareSAML"
)

// GetAuthorizationURLOpts contains the options to pass in order to generate
// an authorization url.
type GetAuthorizationURLOpts struct {
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

// GetProfileAndTokenOpts contains the options to pass in order to get a user profile and access token.
type GetProfileAndTokenOpts struct {
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

	// The user's group memberships. Can be empty.
	Groups []string `json:"groups"`

	// The raw response of Profile attributes from the identity provider
	RawAttributes map[string]interface{} `json:"raw_attributes"`
}

type ProfileAndToken struct {
	// An access token corresponding to the Profile.
	AccessToken string `json:"access_token"`

	// The user Profile.
	Profile Profile `json:"profile"`
}

// GetProfile contains the options to pass in order to get a user profile.
type GetProfileOpts struct {
	// An opaque string provided by the authorization server. It will be
	// exchanged for an Access Token when the user’s profile is sent.
	AccessToken string
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
	Draft      ConnectionState = "draft"
	Active     ConnectionState = "active"
	Inactive   ConnectionState = "inactive"
	Validating ConnectionState = "validating"
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

// ListConnectionsOpts contains the options to request a list of Connections.
type ListConnectionsOpts struct {
	// Authentication service provider descriptor. Can be empty.
	ConnectionType ConnectionType `url:"connection_type,omitempty"`

	// Organization ID of the Connection(s). Can be empty.
	OrganizationID string `url:"organization_id,omitempty"`

	// Domain of a Connection. Can be empty.
	Domain string `url:"domain,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit"`

	// The order in which to paginate records.
	Order common.Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Connection ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Connection ID.
	After string `url:"after,omitempty"`
}

// ListConnectionsResponse describes the response structure when requesting
// existing Connections.
type ListConnectionsResponse struct {
	// List of Connections
	Data []Connection `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// DeleteConnectionOpts contains the options to delete a Connection.
type DeleteConnectionOpts struct {
	// Connection unique identifier.
	Connection string
}

// GetLoginHandler returns an http.Handler that redirects client to the appropriate
// login provider.
func (c *Client) GetLoginHandler(opts GetAuthorizationURLOpts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := c.GetAuthorizationURL(opts)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})
}

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func (c *Client) GetAuthorizationURL(opts GetAuthorizationURLOpts) (*url.URL, error) {
	redirectURI := opts.RedirectURI

	query := make(url.Values, 5)
	query.Set("client_id", c.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")

	if opts.Provider == "" && opts.Connection == "" && opts.Organization == "" {
		return nil, errors.New("incomplete arguments: missing connection, organization, domain, or provider")
	}
	if opts.Provider != "" {
		query.Set("provider", string(opts.Provider))
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

// GetProfileAndToken returns a profile describing the user that authenticated with
// WorkOS SSO.
func (c *Client) GetProfileAndToken(ctx context.Context, opts GetProfileAndTokenOpts) (ProfileAndToken, error) {

	form := make(url.Values, 5)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.APIKey)
	form.Set("grant_type", "authorization_code")
	form.Set("code", opts.Code)

	u, err := url.JoinPath(c.Endpoint, "/sso/token")
	req, err := http.NewRequest(
		http.MethodPost,
		u,
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

// Generic function for making HTTP requests and decoding JSON responses
func performRequest[T any](ctx context.Context, c *Client, method, path string) (T, error) {
	var response T
	u, err := url.JoinPath(c.Endpoint, path)
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return response, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return response, err
	}

	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&response); err != nil {
		return response, err
	}

	return response, nil
}

// GetProfile returns a profile describing the user that authenticated with
// WorkOS SSO.
func (c *Client) GetProfile(ctx context.Context, opts GetProfileOpts) (Profile, error) {
	profile, err := performRequest[Profile](ctx, c, http.MethodGet, "/sso/profile")
	if err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// GetConnection gets a Connection.
func (c *Client) GetConnection(ctx context.Context, opts GetConnectionOpts) (Connection, error) {
	connection, err := performRequest[Connection](ctx, c, http.MethodGet, "/connections")
	if err != nil {
		return Connection{}, err
	}
	return connection, nil
}

// ListConnections gets details of existing Connections.
func (c *Client) ListConnections(ctx context.Context, opts ListConnectionsOpts) (ListConnectionsResponse, error) {
	connections, err := performRequest[ListConnectionsResponse](ctx, c, http.MethodGet, "/connections")
	if err != nil {
		return ListConnectionsResponse{}, err
	}
	return connections, nil
}

// DeleteConnection deletes a Connection.
func (c *Client) DeleteConnection(
	ctx context.Context,
	opts DeleteConnectionOpts,
) error {
	u, err := url.JoinPath(c.Endpoint, "/connections/", opts.Connection)
	req, err := http.NewRequest(
		http.MethodDelete,
		u,
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
