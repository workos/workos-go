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
	clientID string
	baseURL  string
}

// PublicClientOption configures a PublicClient.
type PublicClientOption func(*PublicClient)

// WithPublicClientBaseURL sets a custom base URL for the public client.
func WithPublicClientBaseURL(baseURL string) PublicClientOption {
	return func(p *PublicClient) {
		p.baseURL = baseURL
	}
}

// NewPublicClient creates a public client that only supports PKCE flows (H19).
// No API key is required.
func NewPublicClient(clientID string, opts ...PublicClientOption) *PublicClient {
	p := &PublicClient{
		clientID: clientID,
		baseURL:  defaultBaseURL,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// GetAuthorizationURL builds an AuthKit authorization URL with auto-generated PKCE.
// Returns the authorization URL and the PKCE code verifier that should be stored
// securely for the token exchange step.
func (p *PublicClient) GetAuthorizationURL(params AuthKitAuthorizationURLParams) (*AuthKitPKCEAuthorizationURLResult, error) {
	pkce, err := GeneratePKCEPair()
	if err != nil {
		return nil, fmt.Errorf("workos: failed to generate PKCE pair: %w", err)
	}

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

	// Inject PKCE parameters and client ID into the params.
	params.CodeChallenge = &pkce.CodeChallenge
	params.CodeChallengeMethod = &pkce.CodeChallengeMethod
	if params.ClientID == "" {
		params.ClientID = p.clientID
	}

	// Use a temporary Client to leverage the existing URL builder.
	tempClient := &Client{
		clientID: p.clientID,
		baseURL:  p.baseURL,
	}
	authURL, err := tempClient.GetAuthKitAuthorizationURL(params)
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
	pkce, err := GeneratePKCEPair()
	if err != nil {
		return nil, fmt.Errorf("workos: failed to generate PKCE pair: %w", err)
	}

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

	// Inject PKCE parameters and client ID into the params.
	params.CodeChallenge = &pkce.CodeChallenge
	params.CodeChallengeMethod = &pkce.CodeChallengeMethod
	if params.ClientID == "" {
		params.ClientID = p.clientID
	}

	// Use a temporary Client to leverage the existing URL builder.
	tempClient := &Client{
		clientID: p.clientID,
		baseURL:  p.baseURL,
	}
	authURL, err := tempClient.GetSSOAuthorizationURL(params)
	if err != nil {
		return nil, err
	}

	return &SSOPKCEAuthorizationURLResult{
		URL:          authURL,
		CodeVerifier: pkce.CodeVerifier,
		State:        state,
	}, nil
}
