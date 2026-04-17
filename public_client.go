// @oagen-ignore-file

package workos

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// PublicClient is a client that only supports PKCE-based flows (no API key / client secret).
// It exposes only the helper surface suitable for public/browser clients.
type PublicClient struct {
	client *Client
}

// PublicClientOption configures a PublicClient.
type PublicClientOption func(*publicClientConfig)

// publicClientConfig holds intermediate config before constructing PublicClient.
type publicClientConfig struct {
	baseURL string
}

// WithPublicClientBaseURL sets a custom base URL for the public client.
func WithPublicClientBaseURL(baseURL string) PublicClientOption {
	return func(cfg *publicClientConfig) {
		cfg.baseURL = baseURL
	}
}

// NewPublicClient creates a public client that only supports PKCE flows.
// No API key is required.
func NewPublicClient(clientID string, opts ...PublicClientOption) *PublicClient {
	cfg := &publicClientConfig{
		baseURL: defaultBaseURL,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return &PublicClient{
		client: &Client{
			clientID: clientID,
			baseURL:  cfg.baseURL,
		},
	}
}

// pkceAndState generates a PKCE pair and random state (if state is nil).
func pkceAndState(state *string) (*PKCEPair, string, error) {
	pkce, err := GeneratePKCEPair()
	if err != nil {
		return nil, "", fmt.Errorf("workos: failed to generate PKCE pair: %w", err)
	}
	s := ""
	if state != nil {
		s = *state
	} else {
		stateBytes := make([]byte, 32)
		if _, err := rand.Read(stateBytes); err != nil {
			return nil, "", fmt.Errorf("workos: failed to generate random state: %w", err)
		}
		s = base64.RawURLEncoding.EncodeToString(stateBytes)
	}
	return pkce, s, nil
}

// GetAuthorizationURL builds an AuthKit authorization URL with auto-generated PKCE.
// Returns the authorization URL and the PKCE code verifier that should be stored
// securely for the token exchange step.
func (p *PublicClient) GetAuthorizationURL(params AuthKitAuthorizationURLParams) (*AuthKitPKCEAuthorizationURLResult, error) {
	pkce, state, err := pkceAndState(params.State)
	if err != nil {
		return nil, err
	}

	params.State = &state
	params.CodeChallenge = &pkce.CodeChallenge
	params.CodeChallengeMethod = &pkce.CodeChallengeMethod
	if params.ClientID == "" {
		params.ClientID = p.client.clientID
	}

	authURL, err := p.client.GetAuthKitAuthorizationURL(params)
	if err != nil {
		return nil, err
	}

	return &AuthKitPKCEAuthorizationURLResult{
		URL:          authURL,
		CodeVerifier: pkce.CodeVerifier,
		State:        state,
	}, nil
}

// GetSSOAuthorizationURL builds an SSO authorization URL with auto-generated PKCE.
// Returns the authorization URL and the PKCE code verifier that should be stored
// securely for the token exchange step.
func (p *PublicClient) GetSSOAuthorizationURL(params SSOAuthorizationURLParams) (*SSOPKCEAuthorizationURLResult, error) {
	pkce, state, err := pkceAndState(params.State)
	if err != nil {
		return nil, err
	}

	params.State = &state
	params.CodeChallenge = &pkce.CodeChallenge
	params.CodeChallengeMethod = &pkce.CodeChallengeMethod
	if params.ClientID == "" {
		params.ClientID = p.client.clientID
	}

	authURL, err := p.client.GetSSOAuthorizationURL(params)
	if err != nil {
		return nil, err
	}

	return &SSOPKCEAuthorizationURLResult{
		URL:          authURL,
		CodeVerifier: pkce.CodeVerifier,
		State:        state,
	}, nil
}
