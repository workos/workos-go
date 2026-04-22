// @oagen-ignore-file

package workos_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v7"
)

const testWebhookSecret = "whsec_test_secret_key"

// buildWebhookSigHeader computes a valid signature header for testing.
func buildWebhookSigHeader(secret string, body string, ts time.Time) string {
	timestamp := strconv.FormatInt(ts.Unix(), 10)
	sig := workos.ComputeWebhookSignature(secret, timestamp, body)
	return fmt.Sprintf("t=%s, v1=%s", timestamp, sig)
}

func TestVerifyPayload_ValidSignature(t *testing.T) {
	body := `{"event":"user.created","data":{"id":"user_123"}}`
	now := time.Now()

	sigHeader := buildWebhookSigHeader(testWebhookSecret, body, now)

	verifier := workos.NewWebhookVerifier(testWebhookSecret)
	// Pin the time so the timestamp is within tolerance.
	verifier.SetTolerance(5 * time.Minute)

	result, err := verifier.VerifyPayload(sigHeader, body)
	require.NoError(t, err)
	require.Equal(t, body, result)
}

func TestVerifyPayload_InvalidSignature(t *testing.T) {
	body := `{"event":"user.created"}`
	now := time.Now()
	timestamp := strconv.FormatInt(now.Unix(), 10)

	sigHeader := fmt.Sprintf("t=%s, v1=%s", timestamp, "badsignaturevalue")

	verifier := workos.NewWebhookVerifier(testWebhookSecret)
	_, err := verifier.VerifyPayload(sigHeader, body)
	require.ErrorIs(t, err, workos.ErrWebhookNoValidSignature)
}

func TestVerifyPayload_ExpiredTimestamp(t *testing.T) {
	body := `{"event":"user.created"}`
	// Timestamp from 10 minutes ago (default tolerance is 180s).
	old := time.Now().Add(-10 * time.Minute)

	sigHeader := buildWebhookSigHeader(testWebhookSecret, body, old)

	verifier := workos.NewWebhookVerifier(testWebhookSecret)
	_, err := verifier.VerifyPayload(sigHeader, body)
	require.ErrorIs(t, err, workos.ErrWebhookOutsideTolerance)
}

func TestVerifyPayload_EmptyHeader(t *testing.T) {
	verifier := workos.NewWebhookVerifier(testWebhookSecret)
	_, err := verifier.VerifyPayload("", `{}`)
	require.ErrorIs(t, err, workos.ErrWebhookNotSigned)
}

func TestVerifyPayload_MalformedHeader(t *testing.T) {
	verifier := workos.NewWebhookVerifier(testWebhookSecret)
	_, err := verifier.VerifyPayload("garbage-header", `{}`)
	require.ErrorIs(t, err, workos.ErrWebhookInvalidHeader)
}

func TestConstructEvent_ValidPayload(t *testing.T) {
	body := `{"id":"event_01","object":"event","event":"user.created","created_at":"2024-01-01T00:00:00Z","data":{"id":"user_123"}}`
	now := time.Now()
	sigHeader := buildWebhookSigHeader(testWebhookSecret, body, now)

	verifier := workos.NewWebhookVerifier(testWebhookSecret)
	verifier.SetTolerance(5 * time.Minute)

	event, err := verifier.ConstructEvent(sigHeader, body)
	require.NoError(t, err)
	require.Equal(t, "event_01", event.ID)
	require.Equal(t, "event", event.Object)
	require.Equal(t, "user.created", event.Event)
	require.Equal(t, "user_123", event.Data["id"])
}

func TestComputeWebhookSignature(t *testing.T) {
	sig := workos.ComputeWebhookSignature("secret", "1234567890", `{"hello":"world"}`)
	require.NotEmpty(t, sig)
	// Should be hex-encoded (64 chars for SHA-256).
	require.Len(t, sig, 64)

	// Deterministic: same inputs produce same output.
	sig2 := workos.ComputeWebhookSignature("secret", "1234567890", `{"hello":"world"}`)
	require.Equal(t, sig, sig2)

	// Different secret should produce different signature.
	sig3 := workos.ComputeWebhookSignature("other_secret", "1234567890", `{"hello":"world"}`)
	require.NotEqual(t, sig, sig3)
}

func TestParseWebhookSignatureHeader(t *testing.T) {
	ts, sig, err := workos.ParseWebhookSignatureHeader("t=1234567890, v1=abcdef0123456789")
	require.NoError(t, err)
	require.Equal(t, "1234567890", ts)
	require.Equal(t, "abcdef0123456789", sig)
}

func TestParseWebhookSignatureHeader_Empty(t *testing.T) {
	_, _, err := workos.ParseWebhookSignatureHeader("")
	require.ErrorIs(t, err, workos.ErrWebhookNotSigned)
}

func TestParseWebhookSignatureHeader_MissingV1(t *testing.T) {
	_, _, err := workos.ParseWebhookSignatureHeader("t=1234567890")
	require.ErrorIs(t, err, workos.ErrWebhookInvalidHeader)
}

func TestParseWebhookSignatureHeader_MissingTimestamp(t *testing.T) {
	_, _, err := workos.ParseWebhookSignatureHeader("v1=abcdef")
	require.ErrorIs(t, err, workos.ErrWebhookInvalidHeader)
}
