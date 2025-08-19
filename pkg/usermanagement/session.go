package usermanagement

import (
	"context"
)

type Session struct {
	SealSession    bool   `json:"seal_session,omitempty"`
	CookiePassword string `json:"cookie_password,omitempty"`
}

type SealedSessionOpts struct {
	ClientID       string
	SessionData    string
	CookiePassword string
}

type AuthenticateOpts struct {
	ClientID    string `json:"client_id"`
	SessionData string `json:"session_data"`
}

// AuthenticateWithSessionCookieFailureReason is the set of allowed reasons.
type AuthenticateWithSessionCookieFailureReason string

const (
	ReasonInvalidJWT              AuthenticateWithSessionCookieFailureReason = "invalid_jwt"
	ReasonInvalidSessionCookie    AuthenticateWithSessionCookieFailureReason = "invalid_session_cookie"
	ReasonNoSessionCookieProvided AuthenticateWithSessionCookieFailureReason = "no_session_cookie_provided"
)

// AuthenticateWithSessionCookieResponse is the JSON object returned by authenticate/refresh calls.
type AuthenticateWithSessionCookieResponse struct {
	Authenticated  bool                                        `json:"authenticated"`
	SessionID      string                                      `json:"session_id"`
	User           User                                        `json:"user"`
	OrganizationID string                                      `json:"organization_id,omitempty"`
	Role           string                                      `json:"role,omitempty"`
	Permissions    []string                                    `json:"permissions,omitempty"`
	Entitlements   []string                                    `json:"entitlements,omitempty"`
	Impersonator   Impersonator                                `json:"impersonator,omitempty"`
	Reason         *AuthenticateWithSessionCookieFailureReason `json:"reason,omitempty"`
}

// Authenticate authenticates a user session (package level function)
func Authenticate(ctx context.Context, opts AuthenticateOpts) (AuthenticateWithSessionCookieResponse, error) {
	return DefaultClient.Authenticate(ctx, opts)
}

// LoadSealedSession loads a sealed session (package level function)
func LoadSealedSession(ctx context.Context, opts SealedSessionOpts) (*SessionHelper, error) {
	return DefaultClient.LoadSealedSession(ctx, opts)
}

// Authenticate method on the client
func (c *Client) Authenticate(ctx context.Context, opts AuthenticateOpts) (AuthenticateWithSessionCookieResponse, error) {
	// Create a temporary session helper for authentication
	sessionHelper, err := NewSessionHelper(c, opts.ClientID, opts.SessionData, "")
	if err != nil {
		return AuthenticateWithSessionCookieResponse{}, err
	}

	// Authenticate using the session helper
	result := sessionHelper.Authenticate()

	// Convert to the expected response format
	response := AuthenticateWithSessionCookieResponse{
		Authenticated:  result.Authenticated,
		SessionID:      result.SessionID,
		OrganizationID: result.OrganizationID,
		Role:           result.Role,
		Permissions:    result.Permissions,
		Entitlements:   result.Entitlements,
	}

	// Convert user if it exists
	if result.User != nil {
		if user, ok := result.User.(User); ok {
			response.User = user
		}
	}

	// Convert impersonator if it exists
	if result.Impersonator != nil {
		if impersonator, ok := result.Impersonator.(Impersonator); ok {
			response.Impersonator = impersonator
		}
	}

	// Set reason if authentication failed
	if !result.Authenticated {
		reason := mapFailureReason(result.Reason)
		response.Reason = &reason
	}

	return response, nil
}

// LoadSealedSession method on the client
func (c *Client) LoadSealedSession(ctx context.Context, opts SealedSessionOpts) (*SessionHelper, error) {
	return NewSessionHelper(c, opts.ClientID, opts.SessionData, opts.CookiePassword)
}

func (s *Session) Authenticate(ctx context.Context, opts SealedSessionOpts) (AuthenticateWithSessionCookieResponse, error) {
	// Use the client's authenticate method
	return DefaultClient.Authenticate(ctx, AuthenticateOpts{
		ClientID:    opts.ClientID,
		SessionData: opts.SessionData,
	})
}

// mapFailureReason maps internal failure reasons to the expected enum values
func mapFailureReason(reason string) AuthenticateWithSessionCookieFailureReason {
	switch reason {
	case "INVALID_JWT":
		return ReasonInvalidJWT
	case "INVALID_SESSION_COOKIE":
		return ReasonInvalidSessionCookie
	case "NO_SESSION_COOKIE_PROVIDED":
		return ReasonNoSessionCookieProvided
	default:
		return ReasonInvalidSessionCookie
	}
}
