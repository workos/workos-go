// @oagen-ignore-file

package workos

import (
	"bytes"
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

// WebhookVerifierOption configures a WebhookVerifier.
type WebhookVerifierOption func(*WebhookVerifier)

// WithWebhookTolerance sets the maximum age tolerance for webhook timestamps.
func WithWebhookTolerance(d time.Duration) WebhookVerifierOption {
	return func(w *WebhookVerifier) { w.tolerance = d }
}

// NewWebhookVerifier creates a new verifier with the given secret.
func NewWebhookVerifier(secret string, opts ...WebhookVerifierOption) *WebhookVerifier {
	w := &WebhookVerifier{
		secret:    secret,
		tolerance: 180 * time.Second,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
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

	timestamp, signatures, err := parseWebhookSignatureHeader(sigHeader)
	if err != nil {
		return "", err
	}

	// Validate the timestamp.
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return "", ErrWebhookInvalidTimestamp
	}

	signedAt := time.UnixMilli(ts)
	now := w.now()
	if now.Sub(signedAt).Abs() > w.tolerance {
		return "", ErrWebhookOutsideTolerance
	}

	// Compute the expected signature.
	expected := ComputeWebhookSignature(w.secret, timestamp, body)

	// Constant-time comparison against any v1 signature in the header.
	for _, sig := range signatures {
		if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1 {
			return body, nil
		}
	}

	return "", ErrWebhookNoValidSignature
}

// ConstructEvent verifies the webhook and returns the deserialized event.
// The returned EventSchema carries the standard envelope fields; callers
// can inspect Event/Data to dispatch on event type.
func (w *WebhookVerifier) ConstructEvent(sigHeader string, body string) (*EventSchema, error) {
	verified, err := w.VerifyPayload(sigHeader, body)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(bytes.TrimSpace([]byte(verified)), []byte("null")) {
		return nil, errors.New("workos: invalid webhook event payload")
	}

	var event EventSchema
	if err := json.Unmarshal([]byte(verified), &event); err != nil {
		return nil, fmt.Errorf("workos: failed to parse webhook body: %w", err)
	}
	if event.ID == "" || event.Event == "" {
		return nil, errors.New("workos: webhook event missing required id or event field")
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
	timestamp, signatures, err := parseWebhookSignatureHeader(header)
	if err != nil {
		return "", "", err
	}
	return timestamp, signatures[len(signatures)-1], nil
}

func parseWebhookSignatureHeader(header string) (timestamp string, signatures []string, err error) {
	if header == "" {
		return "", nil, ErrWebhookNotSigned
	}

	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return "", nil, ErrWebhookInvalidHeader
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		switch key {
		case "t":
			timestamp = value
		case "v1":
			if value != "" {
				signatures = append(signatures, value)
			}
		}
	}

	if timestamp == "" || len(signatures) == 0 {
		return "", nil, ErrWebhookInvalidHeader
	}

	return timestamp, signatures, nil
}
