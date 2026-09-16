// @oagen-ignore-file

package workos

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// SessionData represents the unsealed session cookie data.
type SessionData struct {
	AccessToken  string                            `json:"access_token"`
	RefreshToken string                            `json:"refresh_token"`
	User         *User                             `json:"user,omitempty"`
	Impersonator *AuthenticateResponseImpersonator `json:"impersonator,omitempty"`
}

// AuthenticateSessionResult holds the result of authenticating a session.
type AuthenticateSessionResult struct {
	Authenticated  bool
	SessionID      string
	OrganizationID string
	Role           string
	Permissions    []string
	Entitlements   []string
	User           *User
	Impersonator   *AuthenticateResponseImpersonator
	// NeedsRefresh is true when the session cookie was structurally valid
	// but the access-token JWT has expired. Callers should refresh the
	// session (e.g. via Session.Refresh) before treating the user as
	// unauthenticated.
	NeedsRefresh bool
	Reason       string // populated on failure: "no_session_cookie_provided", "invalid_session_cookie", "invalid_jwt", "session_expired", etc.
}

// JWTClaims represents the claims extracted from a session JWT payload.
type JWTClaims struct {
	SessionID      string   `json:"sid"`
	OrganizationID string   `json:"org_id"`
	Role           string   `json:"role"`
	Permissions    []string `json:"permissions"`
	Entitlements   []string `json:"entitlements"`
	// Exp is the JWT expiration claim (seconds since the Unix epoch). Zero
	// when the token did not include an `exp` claim.
	Exp int64 `json:"exp"`
}

// RefreshSessionResult holds the result of refreshing a session.
type RefreshSessionResult struct {
	Authenticated bool
	SealedSession string
	Session       *SessionData
	Reason        string
}

// Session provides session cookie management.
type Session struct {
	client         *Client
	cookiePassword string
	sessionData    string // sealed session cookie value
	issuer         string
}

// SessionOption configures session token verification.
type SessionOption func(*Session)

// WithSessionIssuer sets the trusted access-token issuer for a custom auth domain.
// The default is https://api.workos.com/. This must be trusted configuration,
// never a value taken from an unverified token.
func WithSessionIssuer(issuer string) SessionOption {
	return func(s *Session) { s.issuer = issuer }
}

// NewSession creates a new Session helper. Authentication requires a Client
// configured with WithClientID so access tokens can be verified against its JWKS.
func NewSession(client *Client, sessionData string, cookiePassword string, opts ...SessionOption) *Session {
	s := &Session{
		client:         client,
		cookiePassword: cookiePassword,
		sessionData:    sessionData,
		issuer:         "https://api.workos.com/",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Authenticate unseals the session cookie and verifies the access token's RS256
// signature and claims against the configured client's JWKS before trusting it.
// Uncached JWKS requests have a five-second timeout. Use AuthenticateContext to
// additionally control cancellation with a context.
func (s *Session) Authenticate() (*AuthenticateSessionResult, error) {
	return s.AuthenticateContext(context.Background())
}

// AuthenticateContext authenticates a session using ctx for JWKS requests.
func (s *Session) AuthenticateContext(ctx context.Context) (*AuthenticateSessionResult, error) {
	if s.sessionData == "" {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "no_session_cookie_provided",
		}, nil
	}

	session, err := unsealSession(s.sessionData, s.cookiePassword)
	if err != nil {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "invalid_session_cookie",
		}, nil
	}

	if session.AccessToken == "" {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "invalid_jwt",
		}, nil
	}

	claims, err := s.verifyAccessToken(ctx, session.AccessToken, true)
	if err != nil {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "invalid_jwt",
		}, nil
	}

	// Enforce JWT expiration without extending the token's lifetime, and signal
	// that the caller should refresh only after verifying the token.
	if claims.Exp != 0 && time.Now().Unix() >= claims.Exp {
		return &AuthenticateSessionResult{
			Authenticated:  false,
			NeedsRefresh:   true,
			SessionID:      claims.SessionID,
			OrganizationID: claims.OrganizationID,
			Role:           claims.Role,
			Permissions:    claims.Permissions,
			Entitlements:   claims.Entitlements,
			User:           session.User,
			Impersonator:   session.Impersonator,
			Reason:         "session_expired",
		}, nil
	}

	return &AuthenticateSessionResult{
		Authenticated:  true,
		SessionID:      claims.SessionID,
		OrganizationID: claims.OrganizationID,
		Role:           claims.Role,
		Permissions:    claims.Permissions,
		Entitlements:   claims.Entitlements,
		User:           session.User,
		Impersonator:   session.Impersonator,
	}, nil
}

// Refresh refreshes the session using the refresh token.
//
// On authentication-level failures (revoked refresh token, transient upstream
// errors) the returned error is non-nil and the result carries
// Authenticated=false with a Reason of "refresh_token_revoked" or
// "refresh_failed". Callers should check result.Authenticated (not err == nil)
// as the success signal.
func (s *Session) Refresh(ctx context.Context, opts ...RequestOption) (*RefreshSessionResult, error) {
	if s.sessionData == "" {
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        "no_session_cookie_provided",
		}, nil
	}

	session, err := unsealSession(s.sessionData, s.cookiePassword)
	if err != nil {
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        "invalid_session_cookie",
		}, nil
	}

	if session.RefreshToken == "" {
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        "no_refresh_token",
		}, nil
	}

	if s.client == nil {
		return nil, errors.New("workos: client is required for session refresh")
	}

	// A verified organization_id is only an optional, non-authoritative
	// refresh-request hint, so it is read only when the signing key is already
	// cached: a JWKS request must never consume the context needed to submit
	// the refresh token. Expired tokens are allowed; WorkOS authorizes the
	// refresh token.
	var orgID *string
	if session.AccessToken != "" {
		if claims, err := s.verifyAccessToken(ctx, session.AccessToken, false); err == nil && claims.OrganizationID != "" {
			orgID = &claims.OrganizationID
		}
	}

	authResp, err := s.client.UserManagement().AuthenticateWithRefreshToken(ctx, &UserManagementAuthenticateWithRefreshTokenParams{
		RefreshToken:   session.RefreshToken,
		OrganizationID: orgID,
	}, opts...)
	if err != nil {
		// A terminal refresh failure surfaces as OAuth `invalid_grant` (the
		// refresh token is expired, revoked, or reused past the grace window).
		// The WorkOS token endpoint returns it at HTTP 400 — do not couple the
		// check to a specific status. Any other error (429, 5xx, network, or a
		// lock-timeout surfaced as 429) is transient: the refresh token is
		// still valid, so keep the session and retry rather than signing out.
		reason := "refresh_failed"
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode == "invalid_grant" {
			reason = "refresh_token_revoked"
		}
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        reason,
		}, err
	}

	newSession := &SessionData{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		User:         authResp.User,
		Impersonator: authResp.Impersonator,
	}

	sealed, err := SealSession(newSession, s.cookiePassword)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to seal refreshed session: %w", err)
	}

	return &RefreshSessionResult{
		Authenticated: true,
		SealedSession: sealed,
		Session:       newSession,
	}, nil
}

// GetLogoutURL returns a logout URL for the session.
// The returnTo parameter is optional — pass an empty string to omit it.
func (s *Session) GetLogoutURL(ctx context.Context, returnTo string, opts ...RequestOption) (string, error) {
	if s.sessionData == "" {
		return "", errors.New("workos: no session data provided")
	}

	// Extract the session ID from the cookie. We deliberately do not require
	// result.Authenticated here: an expired access token (Authenticated=false,
	// Reason=session_expired) still has a valid SessionID, and logging out
	// after expiry is the common case. The WorkOS logout endpoint accepts the
	// session ID regardless of access-token freshness.
	result, err := s.AuthenticateContext(ctx)
	if err != nil {
		return "", fmt.Errorf("workos: failed to authenticate session: %w", err)
	}
	if result.SessionID == "" {
		return "", errors.New("workos: session has no session ID")
	}

	baseURL := defaultBaseURL
	if s.client != nil && s.client.baseURL != "" {
		baseURL = s.client.baseURL
	}

	logoutURL := fmt.Sprintf("%s/user_management/sessions/logout?session_id=%s", baseURL, url.QueryEscape(result.SessionID))
	if returnTo != "" {
		logoutURL += "&return_to=" + url.QueryEscape(returnTo)
	}

	return logoutURL, nil
}

// SealSessionFromAuthResponse creates a sealed session cookie from an authentication response.
func SealSessionFromAuthResponse(accessToken string, refreshToken string, user *User, impersonator *AuthenticateResponseImpersonator, cookiePassword string) (string, error) {
	session := &SessionData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
		Impersonator: impersonator,
	}
	return SealSession(session, cookiePassword)
}

// AuthenticateSession cannot authenticate an access token without a configured
// client and fails closed with invalid_jwt for otherwise valid session cookies.
//
// Deprecated: use Client.AuthenticateSession or NewSession with a Client
// configured with WithClientID.
func AuthenticateSession(sealedSession string, cookiePassword string) (*AuthenticateSessionResult, error) {
	result, err := NewSession(nil, sealedSession, cookiePassword).Authenticate()
	if err == nil && result.Reason == "invalid_jwt" {
		err = errors.New("workos: use Client.AuthenticateSession with WithClientID to verify session tokens")
	}
	return result, err
}

// AuthenticateSession verifies a sealed session using this client's configured
// client ID and JWKS endpoint. Options can override the trusted issuer.
func (c *Client) AuthenticateSession(ctx context.Context, sealedSession string, cookiePassword string, opts ...SessionOption) (*AuthenticateSessionResult, error) {
	return NewSession(c, sealedSession, cookiePassword, opts...).AuthenticateContext(ctx)
}

// RefreshSession is a convenience method on Client for one-shot session refresh.
func (c *Client) RefreshSession(ctx context.Context, sealedSession string, cookiePassword string, opts ...RequestOption) (*RefreshSessionResult, error) {
	session := NewSession(c, sealedSession, cookiePassword)
	return session.Refresh(ctx, opts...)
}
