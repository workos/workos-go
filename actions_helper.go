// @oagen-ignore-file

package workos

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// ActionType represents the type of an AuthKit Action.
type ActionType string

const (
	ActionTypeAuthentication   ActionType = "authentication"
	ActionTypeUserRegistration ActionType = "user_registration"
)

// ActionVerdict represents the verdict for an action response.
type ActionVerdict string

const (
	ActionVerdictAllow ActionVerdict = "Allow"
	ActionVerdictDeny  ActionVerdict = "Deny"
)

// ActionsHelper provides helpers for AuthKit Actions request verification and response signing.
type ActionsHelper struct {
	tolerance time.Duration
	now       func() time.Time
}

// NewActionsHelper creates a new ActionsHelper.
func NewActionsHelper() *ActionsHelper {
	return &ActionsHelper{
		tolerance: 30 * time.Second,
		now:       time.Now,
	}
}

// VerifyHeader verifies the signature of an Actions webhook request.
func (a *ActionsHelper) VerifyHeader(payload string, sigHeader string, secret string) error {
	if sigHeader == "" {
		return ErrWebhookNotSigned
	}

	timestamp, signature, err := ParseWebhookSignatureHeader(sigHeader)
	if err != nil {
		return err
	}

	// Validate the timestamp.
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrWebhookInvalidTimestamp
	}

	signedAt := time.Unix(ts, 0)
	now := a.now()
	if now.Sub(signedAt).Abs() > a.tolerance {
		return ErrWebhookOutsideTolerance
	}

	// Compute the expected signature.
	expected := ComputeWebhookSignature(secret, timestamp, payload)

	// Constant-time comparison.
	if subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) != 1 {
		return ErrWebhookNoValidSignature
	}

	return nil
}

// ActionSignedResponse is the result of signing an action response.
// Send Payload and Sig back to WorkOS as the action webhook response body.
type ActionSignedResponse struct {
	// Payload is the base64-encoded JSON response body.
	Payload string `json:"payload"`
	// Sig is the signature header in the form "t=<timestamp>,v1=<hex>".
	Sig string `json:"sig"`
}

// ConstructAction verifies and deserializes an Actions request into the
// standard WorkOS event envelope. Callers can inspect Event/Data to
// dispatch on action type.
func (a *ActionsHelper) ConstructAction(payload string, sigHeader string, secret string) (*EventSchema, error) {
	if err := a.VerifyHeader(payload, sigHeader, secret); err != nil {
		return nil, err
	}

	var action EventSchema
	if err := json.Unmarshal([]byte(payload), &action); err != nil {
		return nil, fmt.Errorf("workos: failed to parse action payload: %w", err)
	}
	return &action, nil
}

// SignResponse signs an action response with the given secret.
func (a *ActionsHelper) SignResponse(actionType ActionType, verdict ActionVerdict, errorMessage string, secret string) (*ActionSignedResponse, error) {
	responsePayload := map[string]interface{}{
		"type":          string(actionType),
		"verdict":       string(verdict),
		"error_message": errorMessage,
	}

	jsonBytes, err := json.Marshal(responsePayload)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to marshal action response: %w", err)
	}

	b64Payload := base64.StdEncoding.EncodeToString(jsonBytes)

	now := a.now()
	timestamp := strconv.FormatInt(now.Unix(), 10)

	sig := ComputeWebhookSignature(secret, timestamp, b64Payload)

	return &ActionSignedResponse{
		Payload: b64Payload,
		Sig:     fmt.Sprintf("t=%s,v1=%s", timestamp, sig),
	}, nil
}
