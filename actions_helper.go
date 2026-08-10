// @oagen-ignore-file

package workos

import (
	"bytes"
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

	signedAt := time.UnixMilli(ts)
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

// ActionContext is the context sent to an Actions endpoint.
type ActionContext struct {
	Object                 string                  `json:"object"`
	ID                     string                  `json:"id"`
	User                   *User                   `json:"user,omitempty"`
	Organization           *Organization           `json:"organization,omitempty"`
	OrganizationMembership *OrganizationMembership `json:"organization_membership,omitempty"`
	UserData               *ActionUserData         `json:"user_data,omitempty"`
	Invitation             *Invitation             `json:"invitation,omitempty"`
	IPAddress              string                  `json:"ip_address,omitempty"`
	UserAgent              string                  `json:"user_agent,omitempty"`
	DeviceFingerprint      string                  `json:"device_fingerprint,omitempty"`
	Issuer                 string                  `json:"issuer,omitempty"`
}

// ActionUserData is the user data sent in a user registration action.
type ActionUserData struct {
	Object    string  `json:"object"`
	Email     string  `json:"email"`
	Name      *string `json:"name"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
}

// ActionResponsePayload is the signed payload in an action response.
type ActionResponsePayload struct {
	Timestamp    int64         `json:"timestamp"`
	Verdict      ActionVerdict `json:"verdict"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// ActionResponse is the response body to send to WorkOS.
type ActionResponse struct {
	Object    string                `json:"object"`
	Payload   ActionResponsePayload `json:"payload"`
	Signature string                `json:"signature"`
}

// ActionSignedResponse preserves the original v10 response fields.
//
// Deprecated: Use ActionResponse and SignActionResponse instead.
type ActionSignedResponse struct {
	Payload  string `json:"-"`
	Sig      string `json:"-"`
	response *ActionResponse
}

// MarshalJSON emits the Actions API wire format while preserving the legacy fields for source compatibility.
func (r ActionSignedResponse) MarshalJSON() ([]byte, error) {
	if r.response != nil {
		return json.Marshal(r.response)
	}
	return json.Marshal(struct {
		Payload string `json:"payload"`
		Sig     string `json:"sig"`
	}{Payload: r.Payload, Sig: r.Sig})
}

// ConstructAction verifies and deserializes an Actions request into an
// ActionContext. Dispatch on Object to read the type-specific fields.
func (a *ActionsHelper) ConstructAction(payload string, sigHeader string, secret string) (*ActionContext, error) {
	if err := a.VerifyHeader(payload, sigHeader, secret); err != nil {
		return nil, err
	}

	var action ActionContext
	if err := json.Unmarshal([]byte(payload), &action); err != nil {
		return nil, fmt.Errorf("workos: failed to parse action payload: %w", err)
	}
	if action.Object != "authentication_action_context" && action.Object != "user_registration_action_context" {
		return nil, fmt.Errorf("workos: unsupported action object %q", action.Object)
	}
	return &action, nil
}

// SignResponse preserves the original v10 return type while emitting the correct wire format when JSON encoded.
//
// Deprecated: Use SignActionResponse for a typed Actions API response.
func (a *ActionsHelper) SignResponse(actionType ActionType, verdict ActionVerdict, errorMessage string, secret string) (*ActionSignedResponse, error) {
	response, err := a.SignActionResponse(actionType, verdict, errorMessage, secret)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := marshalActionResponsePayload(response.Payload)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(response.Payload.Timestamp, 10)
	return &ActionSignedResponse{
		Payload:  base64.StdEncoding.EncodeToString(payloadJSON),
		Sig:      fmt.Sprintf("t=%s,v1=%s", timestamp, response.Signature),
		response: response,
	}, nil
}

// SignActionResponse signs an action response with the given secret.
func (a *ActionsHelper) SignActionResponse(actionType ActionType, verdict ActionVerdict, errorMessage string, secret string) (*ActionResponse, error) {
	var object string
	switch actionType {
	case ActionTypeAuthentication:
		object = "authentication_action_response"
	case ActionTypeUserRegistration:
		object = "user_registration_action_response"
	default:
		return nil, fmt.Errorf("workos: unsupported action type %q", actionType)
	}
	if verdict != ActionVerdictAllow && verdict != ActionVerdictDeny {
		return nil, fmt.Errorf("workos: unsupported action verdict %q", verdict)
	}

	payload := ActionResponsePayload{
		Timestamp: a.now().UnixMilli(),
		Verdict:   verdict,
	}
	if verdict == ActionVerdictDeny {
		payload.ErrorMessage = errorMessage
	}

	payloadJSON, err := marshalActionResponsePayload(payload)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(payload.Timestamp, 10)

	return &ActionResponse{
		Object:    object,
		Payload:   payload,
		Signature: ComputeWebhookSignature(secret, timestamp, string(payloadJSON)),
	}, nil
}

func marshalActionResponsePayload(payload ActionResponsePayload) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return nil, fmt.Errorf("workos: failed to marshal action response: %w", err)
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}
