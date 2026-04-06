// @oagen-ignore-file

package workos

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
)

// SSOAuthorizationURLParams are parameters for building an SSO authorization URL.
type SSOAuthorizationURLParams struct {
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
}

// GetSSOAuthorizationURL builds an SSO authorization URL client-side (H14).
func (c *Client) GetSSOAuthorizationURL(params SSOAuthorizationURLParams) (string, error) {
	clientID := params.ClientID
	if clientID == "" {
		clientID = c.clientID
	}
	if clientID == "" {
		return "", fmt.Errorf("workos: client_id is required for SSO authorization URL")
	}
	if params.RedirectURI == "" {
		return "", fmt.Errorf("workos: redirect_uri is required for SSO authorization URL")
	}

	baseURL := c.baseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	u, err := url.Parse(baseURL + "/sso/authorize")
	if err != nil {
		return "", fmt.Errorf("workos: failed to parse SSO authorization URL: %w", err)
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

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SSOPKCEAuthorizationURLResult holds the URL and PKCE verifier.
type SSOPKCEAuthorizationURLResult struct {
	URL          string
	CodeVerifier string
	State        string
}

// GetSSOPKCEAuthorizationURL generates PKCE parameters and builds an SSO authorization URL (H15).
func (c *Client) GetSSOPKCEAuthorizationURL(params SSOAuthorizationURLParams) (*SSOPKCEAuthorizationURLResult, error) {
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

	authURL, err := c.GetSSOAuthorizationURL(params)
	if err != nil {
		return nil, err
	}

	return &SSOPKCEAuthorizationURLResult{
		URL:          authURL,
		CodeVerifier: pair.CodeVerifier,
		State:        state,
	}, nil
}

// SSOPKCECodeExchangeParams for SSO PKCE code exchange.
type SSOPKCECodeExchangeParams struct {
	Code         string
	CodeVerifier string
}

// SSOPKCECodeExchange exchanges an SSO authorization code with PKCE (H16).
func (c *Client) SSOPKCECodeExchange(ctx context.Context, params SSOPKCECodeExchangeParams, opts ...RequestOption) (*SSOTokenResponse, error) {
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

	var result SSOTokenResponse
	_, err := c.request(ctx, "POST", "/sso/token", nil, body, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// SSOLogoutParams holds parameters for SSO logout.
type SSOLogoutParams struct {
	SessionID string
	ReturnTo  *string
}

// SSOLogout initiates a logout flow (H17).
// First obtains a logout token via AuthorizeLogout, then builds the logout redirect URL.
func (c *Client) SSOLogout(ctx context.Context, params SSOLogoutParams, opts ...RequestOption) (string, error) {
	// Step 1: Call AuthorizeLogout to get a logout token.
	logoutResp, err := c.SSO().AuthorizeLogout(ctx, &SSOAuthorizeLogoutParams{
		ProfileID: params.SessionID,
	}, opts...)
	if err != nil {
		return "", err
	}

	// Step 2: Build the logout redirect URL.
	baseURL := c.baseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	u, err := url.Parse(baseURL + "/sso/logout")
	if err != nil {
		return "", fmt.Errorf("workos: failed to parse logout URL: %w", err)
	}

	q := u.Query()
	q.Set("token", logoutResp.LogoutToken)
	if params.ReturnTo != nil {
		q.Set("return_to", *params.ReturnTo)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
