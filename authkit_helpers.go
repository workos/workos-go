// @oagen-ignore-file

package workos

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// AuthKitAuthorizationURLParams are parameters for building an AuthKit authorization URL.
type AuthKitAuthorizationURLParams struct {
	RedirectURI         string
	ClientID            string // if empty, uses client's configured clientID
	Provider            *string
	ConnectionID        *string
	OrganizationID      *string
	DomainHint          *string
	LoginHint           *string
	State               *string
	CodeChallenge       *string
	CodeChallengeMethod *string
	ScreenHint          *string
}

// GetAuthKitAuthorizationURL builds an AuthKit authorization URL.
// This is a helper that constructs the URL client-side without making an HTTP request.
func (c *Client) GetAuthKitAuthorizationURL(params AuthKitAuthorizationURLParams) (string, error) {
	clientID := params.ClientID
	if clientID == "" {
		clientID = c.clientID
	}
	if clientID == "" {
		return "", fmt.Errorf("workos: client_id is required for AuthKit authorization URL")
	}
	if params.RedirectURI == "" {
		return "", fmt.Errorf("workos: redirect_uri is required for AuthKit authorization URL")
	}

	baseURL := c.baseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	u, err := url.Parse(baseURL + "/user_management/authorize")
	if err != nil {
		return "", fmt.Errorf("workos: failed to parse authorization URL: %w", err)
	}

	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", params.RedirectURI)
	q.Set("response_type", "code")

	if params.Provider != nil {
		q.Set("provider", *params.Provider)
	}
	if params.ConnectionID != nil {
		q.Set("connection_id", *params.ConnectionID)
	}
	if params.OrganizationID != nil {
		q.Set("organization_id", *params.OrganizationID)
	}
	if params.DomainHint != nil {
		q.Set("domain_hint", *params.DomainHint)
	}
	if params.LoginHint != nil {
		q.Set("login_hint", *params.LoginHint)
	}
	if params.State != nil {
		q.Set("state", *params.State)
	}
	if params.CodeChallenge != nil {
		q.Set("code_challenge", *params.CodeChallenge)
	}
	if params.CodeChallengeMethod != nil {
		q.Set("code_challenge_method", *params.CodeChallengeMethod)
	}
	if params.ScreenHint != nil {
		q.Set("screen_hint", *params.ScreenHint)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// AuthKitPKCEAuthorizationURLResult contains the authorization URL plus the PKCE code verifier.
type AuthKitPKCEAuthorizationURLResult struct {
	URL          string
	CodeVerifier string
	State        string
}

// GetAuthKitPKCEAuthorizationURL generates PKCE parameters and builds an AuthKit authorization URL.
func (c *Client) GetAuthKitPKCEAuthorizationURL(params AuthKitAuthorizationURLParams) (*AuthKitPKCEAuthorizationURLResult, error) {
	pair, err := GeneratePKCEPair()
	if err != nil {
		return nil, fmt.Errorf("workos: failed to generate PKCE pair: %w", err)
	}

	params.CodeChallenge = &pair.CodeChallenge
	params.CodeChallengeMethod = &pair.CodeChallengeMethod

	// Generate a random state if not provided.
	state := ""
	if params.State != nil {
		state = *params.State
	} else {
		stateBytes := make([]byte, 32)
		if _, err := rand.Read(stateBytes); err != nil {
			return nil, fmt.Errorf("workos: failed to generate random state: %w", err)
		}
		state = base64.RawURLEncoding.EncodeToString(stateBytes)
		params.State = &state
	}

	authURL, err := c.GetAuthKitAuthorizationURL(params)
	if err != nil {
		return nil, err
	}

	return &AuthKitPKCEAuthorizationURLResult{
		URL:          authURL,
		CodeVerifier: pair.CodeVerifier,
		State:        state,
	}, nil
}

// AuthKitPKCECodeExchangeParams holds the parameters for PKCE code exchange.
type AuthKitPKCECodeExchangeParams struct {
	Code         string
	CodeVerifier string
}

// AuthKitPKCECodeExchange exchanges an authorization code with a code verifier.
// This calls the authenticate endpoint with the code_verifier parameter.
func (c *Client) AuthKitPKCECodeExchange(ctx context.Context, params AuthKitPKCECodeExchangeParams, opts ...RequestOption) (*AuthenticateResponse, error) {
	clientID := c.clientID
	body := map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          params.Code,
		"code_verifier": params.CodeVerifier,
	}
	if clientID != "" {
		body["client_id"] = clientID
	}
	if c.apiKey != "" {
		body["client_secret"] = c.apiKey
	}

	var result AuthenticateResponse
	_, err := c.request(ctx, "POST", "/user_management/authenticate", nil, body, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// AuthKitStartDeviceAuthorization initiates a device authorization flow (part 1).
func (c *Client) AuthKitStartDeviceAuthorization(ctx context.Context, opts ...RequestOption) (*DeviceAuthorizationResponse, error) {
	return c.UserManagement().CreateDevice(ctx, &UserManagementCreateDeviceParams{
		ClientID: c.clientID,
	}, opts...)
}

// AuthKitPollDeviceCode polls for device code completion (part 2).
// Returns the authentication response once the user completes authorization.
// This method blocks until authorization completes, an error occurs, or the context is cancelled.
func (c *Client) AuthKitPollDeviceCode(ctx context.Context, deviceCode string, interval int, opts ...RequestOption) (*AuthenticateResponse, error) {
	if interval <= 0 {
		interval = 5
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			resp, err := c.UserManagement().AuthenticateWithDeviceCode(ctx, &AuthenticateWithDeviceCodeParams{
				DeviceCode: deviceCode,
			}, opts...)
			if err != nil {
				// Check if this is an "authorization_pending" error; if so, keep polling.
				var apiErr *APIError
				if errors.As(err, &apiErr) && apiErr.Code == "authorization_pending" {
					continue
				}
				return nil, err
			}
			return resp, nil
		}
	}
}
