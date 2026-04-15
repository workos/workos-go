// @oagen-ignore-file

package workos

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors for webhook verification.
var (
	ErrWebhookInvalidHeader    = errors.New("workos: invalid webhook signature header")
	ErrWebhookNoValidSignature = errors.New("workos: no valid signature found")
	ErrWebhookNotSigned        = errors.New("workos: webhook not signed")
	ErrWebhookInvalidTimestamp = errors.New("workos: invalid timestamp in signature header")
	ErrWebhookOutsideTolerance = errors.New("workos: timestamp outside tolerance")
)

// WebhookVerifier verifies WorkOS webhook signatures.
type WebhookVerifier struct {
	secret    string
	tolerance time.Duration
	now       func() time.Time
}

// NewWebhookVerifier creates a new verifier with the given secret.
func NewWebhookVerifier(secret string) *WebhookVerifier {
	return &WebhookVerifier{
		secret:    secret,
		tolerance: 180 * time.Second,
		now:       time.Now,
	}
}

// SetTolerance sets the maximum age tolerance for webhook timestamps.
func (w *WebhookVerifier) SetTolerance(d time.Duration) {
	w.tolerance = d
}

// VerifyPayload verifies a webhook signature header against the body and returns the verified body.
// The sigHeader format is "t=<timestamp>, v1=<signature>".
func (w *WebhookVerifier) VerifyPayload(sigHeader string, body string) (string, error) {
	if sigHeader == "" {
		return "", ErrWebhookNotSigned
	}

	timestamp, signature, err := ParseWebhookSignatureHeader(sigHeader)
	if err != nil {
		return "", err
	}

	// Validate the timestamp.
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return "", ErrWebhookInvalidTimestamp
	}

	signedAt := time.Unix(ts, 0)
	now := w.now()
	if now.Sub(signedAt).Abs() > w.tolerance {
		return "", ErrWebhookOutsideTolerance
	}

	// Compute the expected signature.
	expected := ComputeWebhookSignature(w.secret, timestamp, body)

	// Constant-time comparison.
	if subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) != 1 {
		return "", ErrWebhookNoValidSignature
	}

	return body, nil
}

// ConstructEvent verifies the webhook and returns the deserialized event.
// The returned EventSchema carries the standard envelope fields; callers
// can inspect Event/Data to dispatch on event type.
func (w *WebhookVerifier) ConstructEvent(sigHeader string, body string) (*EventSchema, error) {
	verified, err := w.VerifyPayload(sigHeader, body)
	if err != nil {
		return nil, err
	}

	var event EventSchema
	if err := json.Unmarshal([]byte(verified), &event); err != nil {
		return nil, fmt.Errorf("workos: failed to parse webhook body: %w", err)
	}
	return &event, nil
}

// ComputeWebhookSignature computes the HMAC-SHA256 signature for a webhook payload.
func ComputeWebhookSignature(secret string, timestamp string, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// ParseWebhookSignatureHeader parses the "t=..., v1=..." header into timestamp and signature.
func ParseWebhookSignatureHeader(header string) (timestamp string, signature string, err error) {
	if header == "" {
		return "", "", ErrWebhookNotSigned
	}

	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return "", "", ErrWebhookInvalidHeader
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		switch key {
		case "t":
			timestamp = value
		case "v1":
			signature = value
		}
	}

	if timestamp == "" || signature == "" {
		return "", "", ErrWebhookInvalidHeader
	}

	return timestamp, signature, nil
}
