// @oagen-ignore-file

package workos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SessionData represents the unsealed session cookie data.
type SessionData struct {
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	User         map[string]interface{} `json:"user,omitempty"`
	Impersonator map[string]interface{} `json:"impersonator,omitempty"`
}

// AuthenticateSessionResult holds the result of authenticating a session.
type AuthenticateSessionResult struct {
	Authenticated  bool
	SessionID      string
	OrganizationID string
	Role           string
	Permissions    []string
	Entitlements   []string
	User           map[string]interface{}
	Impersonator   map[string]interface{}
	Reason         string // populated on failure: "no_session_cookie_provided", "invalid_session_cookie", "invalid_jwt", etc.
}

// RefreshSessionResult holds the result of refreshing a session.
type RefreshSessionResult struct {
	Authenticated bool
	SealedSession string
	Session       *SessionData
	Reason        string
}

// Session provides session cookie management (H04).
type Session struct {
	client         *Client
	cookiePassword string
	sessionData    string // sealed session cookie value
}

// NewSession creates a new Session helper (H04).
func NewSession(client *Client, sessionData string, cookiePassword string) *Session {
	return &Session{
		client:         client,
		cookiePassword: cookiePassword,
		sessionData:    sessionData,
	}
}

// Authenticate validates the session cookie (H04).
// Unseals the session data, validates that the access token is present,
// and extracts claims from the JWT payload.
func (s *Session) Authenticate() (*AuthenticateSessionResult, error) {
	if s.sessionData == "" {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "no_session_cookie_provided",
		}, nil
	}

	unsealed, err := UnsealData(s.sessionData, s.cookiePassword)
	if err != nil {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "invalid_session_cookie",
		}, nil
	}

	accessToken, _ := unsealed["access_token"].(string)
	if accessToken == "" {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "invalid_jwt",
		}, nil
	}

	claims, err := parseJWTPayload(accessToken)
	if err != nil {
		return &AuthenticateSessionResult{
			Authenticated: false,
			Reason:        "invalid_jwt",
		}, nil
	}

	sessionID, _ := claims["sid"].(string)
	organizationID, _ := claims["org_id"].(string)
	role, _ := claims["role"].(string)

	permissions := extractStringSlice(claims, "permissions")
	entitlements := extractStringSlice(claims, "entitlements")

	// Extract user and impersonator from the unsealed data.
	var user map[string]interface{}
	if u, ok := unsealed["user"]; ok {
		user, _ = u.(map[string]interface{})
	}
	var impersonator map[string]interface{}
	if imp, ok := unsealed["impersonator"]; ok {
		impersonator, _ = imp.(map[string]interface{})
	}

	return &AuthenticateSessionResult{
		Authenticated:  true,
		SessionID:      sessionID,
		OrganizationID: organizationID,
		Role:           role,
		Permissions:    permissions,
		Entitlements:   entitlements,
		User:           user,
		Impersonator:   impersonator,
	}, nil
}

// Refresh refreshes the session using the refresh token (H04).
func (s *Session) Refresh(ctx context.Context, opts ...RequestOption) (*RefreshSessionResult, error) {
	if s.sessionData == "" {
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        "no_session_cookie_provided",
		}, nil
	}

	unsealed, err := UnsealData(s.sessionData, s.cookiePassword)
	if err != nil {
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        "invalid_session_cookie",
		}, nil
	}

	refreshToken, _ := unsealed["refresh_token"].(string)
	if refreshToken == "" {
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        "no_refresh_token",
		}, nil
	}

	if s.client == nil {
		return nil, errors.New("workos: client is required for session refresh")
	}

	// Extract organization_id from the unsealed data for the refresh request.
	var orgID *string
	if oid, ok := unsealed["organization_id"].(string); ok && oid != "" {
		orgID = &oid
	}

	authResp, err := s.client.UserManagement().AuthenticateWithRefreshToken(ctx, &AuthenticateWithRefreshTokenParams{
		RefreshToken:   refreshToken,
		OrganizationID: orgID,
	}, opts...)
	if err != nil {
		return &RefreshSessionResult{
			Authenticated: false,
			Reason:        "refresh_failed",
		}, nil
	}

	// Build user map from the auth response.
	var userMap map[string]interface{}
	if authResp.User != nil {
		userBytes, err := json.Marshal(authResp.User)
		if err == nil {
			json.Unmarshal(userBytes, &userMap)
		}
	}

	// Build impersonator map from the auth response.
	var impersonatorMap map[string]interface{}
	if authResp.Impersonator != nil {
		impBytes, err := json.Marshal(authResp.Impersonator)
		if err == nil {
			json.Unmarshal(impBytes, &impersonatorMap)
		}
	}

	newSession := &SessionData{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		User:         userMap,
		Impersonator: impersonatorMap,
	}

	sealed, err := SealSessionFromAuthResponse(
		authResp.AccessToken,
		authResp.RefreshToken,
		userMap,
		impersonatorMap,
		s.cookiePassword,
	)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to seal refreshed session: %w", err)
	}

	return &RefreshSessionResult{
		Authenticated: true,
		SealedSession: sealed,
		Session:       newSession,
	}, nil
}

// GetLogoutURL returns a logout URL for the session (H04).
// The returnTo parameter is optional — pass an empty string to omit it.
func (s *Session) GetLogoutURL(ctx context.Context, returnTo string, opts ...RequestOption) (string, error) {
	if s.sessionData == "" {
		return "", errors.New("workos: no session data provided")
	}

	// Authenticate to extract the session ID.
	result, err := s.Authenticate()
	if err != nil {
		return "", fmt.Errorf("workos: failed to authenticate session: %w", err)
	}
	if !result.Authenticated || result.SessionID == "" {
		return "", errors.New("workos: session is not authenticated or has no session ID")
	}

	baseURL := defaultBaseURL
	if s.client != nil && s.client.baseURL != "" {
		baseURL = s.client.baseURL
	}

	logoutURL := fmt.Sprintf("%s/user_management/sessions/logout?session_id=%s", baseURL, result.SessionID)
	if returnTo != "" {
		logoutURL += "&return_to=" + returnTo
	}

	return logoutURL, nil
}

// SealSessionFromAuthResponse creates a sealed session cookie from an authentication response (H07).
func SealSessionFromAuthResponse(accessToken string, refreshToken string, user map[string]interface{}, impersonator map[string]interface{}, cookiePassword string) (string, error) {
	data := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	if user != nil {
		data["user"] = user
	}
	if impersonator != nil {
		data["impersonator"] = impersonator
	}

	return SealData(data, cookiePassword)
}

// AuthenticateSession is a convenience method for one-shot session authentication (H05).
// It does not require a Client — only the sealed session and cookie password.
func AuthenticateSession(sealedSession string, cookiePassword string) (*AuthenticateSessionResult, error) {
	session := NewSession(nil, sealedSession, cookiePassword)
	return session.Authenticate()
}

// RefreshSession is a convenience method on Client for one-shot session refresh (H05).
func (c *Client) RefreshSession(ctx context.Context, sealedSession string, cookiePassword string, opts ...RequestOption) (*RefreshSessionResult, error) {
	session := NewSession(c, sealedSession, cookiePassword)
	return session.Refresh(ctx, opts...)
}

// parseJWTPayload extracts and decodes the payload (claims) from a JWT.
// It does not verify the signature — this is acceptable because the JWT was
// sealed by us and is trusted after unsealing.
func parseJWTPayload(token string) (map[string]interface{}, error) {
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

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("workos: failed to unmarshal JWT claims: %w", err)
	}

	return claims, nil
}

// extractStringSlice extracts a []string from a map value that may be
// []interface{} (the default json.Unmarshal representation of a JSON array).
func extractStringSlice(m map[string]interface{}, key string) []string {
	val, ok := m[key]
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return v
	default:
		return nil
	}
}
