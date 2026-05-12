// @oagen-ignore-file

package workos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
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
	// Err is the underlying error that produced an authentication-level
	// failure (e.g. a *APIError from AuthenticateWithRefreshToken). It is
	// populated alongside Reason on the "refresh_token_revoked" and
	// "refresh_failed" paths so callers can recover status code, error
	// code, and request ID via errors.As — without changing Refresh's
	// `(result, nil)` return contract.
	Err error
}

// Session provides session cookie management.
type Session struct {
	client         *Client
	cookiePassword string
	sessionData    string // sealed session cookie value
}

// NewSession creates a new Session helper.
func NewSession(client *Client, sessionData string, cookiePassword string) *Session {
	return &Session{
		client:         client,
		cookiePassword: cookiePassword,
		sessionData:    sessionData,
	}
}

// Authenticate validates the session cookie.
// Unseals the session data, validates that the access token is present,
// and extracts claims from the JWT payload.
func (s *Session) Authenticate() (*AuthenticateSessionResult, error) {
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

	claims, err := parseJWTPayload(session.AccessToken)
	if err != nil {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "invalid_jwt",
		}, nil
	}

	// Enforce JWT expiration. Treat tokens whose `exp` claim is in the past
	// as expired and signal that the caller should refresh the session.
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

	// Extract organization_id from the JWT claims for the refresh request.
	var orgID *string
	if session.AccessToken != "" {
		if claims, err := parseJWTPayload(session.AccessToken); err == nil && claims.OrganizationID != "" {
			orgID = &claims.OrganizationID
		}
	}

	authResp, err := s.client.UserManagement().AuthenticateWithRefreshToken(ctx, &UserManagementAuthenticateWithRefreshTokenParams{
		RefreshToken:   session.RefreshToken,
		OrganizationID: orgID,
	}, opts...)
	if err != nil {
		// Distinguish a permanently revoked / invalid refresh token (401
		// invalid_grant) from a transient failure (5xx, network errors,
		// rate limit). The underlying error is exposed on result.Err so
		// callers can recover the typed *APIError via errors.As without
		// changing Refresh's `(result, nil)` return contract for
		// authentication-level failures.
		reason := "refresh_failed"
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 401 && apiErr.ErrorCode == "invalid_grant" {
			reason = "refresh_token_revoked"
		}
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        reason,
			Err:           err,
		}, nil
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
	result, err := s.Authenticate()
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

// AuthenticateSession is a convenience method for one-shot session authentication.
// It does not require a Client — only the sealed session and cookie password.
func AuthenticateSession(sealedSession string, cookiePassword string) (*AuthenticateSessionResult, error) {
	session := NewSession(nil, sealedSession, cookiePassword)
	return session.Authenticate()
}

// RefreshSession is a convenience method on Client for one-shot session refresh.
func (c *Client) RefreshSession(ctx context.Context, sealedSession string, cookiePassword string, opts ...RequestOption) (*RefreshSessionResult, error) {
	session := NewSession(c, sealedSession, cookiePassword)
	return session.Refresh(ctx, opts...)
}

// parseJWTPayload extracts and decodes the payload (claims) from a JWT.
// It does not verify the signature — this is acceptable because the JWT was
// sealed by us and is trusted after unsealing.
func parseJWTPayload(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("workos: invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload := parts[1]

	// Base64url decode — the standard library's RawURLEncoding handles the
	// URL-safe alphabet and no-padding variant used by JWTs.
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to decode JWT payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("workos: failed to unmarshal JWT claims: %w", err)
	}

	return &claims, nil
}
