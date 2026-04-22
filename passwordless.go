// @oagen-ignore-file

package workos

import (
	"context"
	"fmt"
)

// PasswordlessService handles Passwordless session operations.
type PasswordlessService struct {
	client *Client
}

// PasswordlessSession represents a passwordless session.
type PasswordlessSession struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	ExpiresAt string `json:"expires_at"`
	Link      string `json:"link"`
	Object    string `json:"object"`
}

// PasswordlessSessionType is the type of passwordless session.
type PasswordlessSessionType string

// PasswordlessSessionTypeMagicLink is the MagicLink session type.
const PasswordlessSessionTypeMagicLink PasswordlessSessionType = "MagicLink"

// PasswordlessCreateSessionParams are the parameters for creating a passwordless session.
type PasswordlessCreateSessionParams struct {
	Email       string                  `json:"email"`
	Type        PasswordlessSessionType `json:"type"`
	RedirectURI *string                 `json:"redirect_uri,omitempty"`
	State       *string                 `json:"state,omitempty"`
	ExpiresIn   *int                    `json:"expires_in,omitempty"`
}

// CreateSession creates a new passwordless session (POST /passwordless/sessions).
func (s *PasswordlessService) CreateSession(ctx context.Context, params *PasswordlessCreateSessionParams, opts ...RequestOption) (*PasswordlessSession, error) {
	var result PasswordlessSession
	_, err := s.client.request(ctx, "POST", "/passwordless/sessions", nil, params, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// SendSession sends the magic-link email for a session (POST /passwordless/sessions/{id}/send).
func (s *PasswordlessService) SendSession(ctx context.Context, sessionID string, opts ...RequestOption) error {
	_, err := s.client.request(ctx, "POST", fmt.Sprintf("/passwordless/sessions/%s/send", sessionID), nil, nil, nil, opts)
	return err
}
