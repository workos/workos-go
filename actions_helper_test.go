// @oagen-ignore-file

package workos_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6"
)

const testActionSecret = "action_secret_key"

// computeTestActionSignature computes an HMAC-SHA256 signature for action tests.
func computeTestActionSignature(secret, timestamp, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// buildActionSigHeader builds a "t=...,v1=..." signature header for testing.
func buildActionSigHeader(secret, payload string, ts time.Time) string {
	timestamp := strconv.FormatInt(ts.Unix(), 10)
	sig := computeTestActionSignature(secret, timestamp, payload)
	return fmt.Sprintf("t=%s,v1=%s", timestamp, sig)
}

func TestActionsHelper_VerifyHeader_Valid(t *testing.T) {
	payload := `{"type":"authentication","action_id":"action_123"}`
	now := time.Now()
	sigHeader := buildActionSigHeader(testActionSecret, payload, now)

	helper := workos.NewActionsHelper()
	err := helper.VerifyHeader(payload, sigHeader, testActionSecret)
	require.NoError(t, err)
}

func TestActionsHelper_VerifyHeader_InvalidSignature(t *testing.T) {
	payload := `{"type":"authentication"}`
	now := time.Now()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	sigHeader := fmt.Sprintf("t=%s,v1=%s", timestamp, "invalidsig")

	helper := workos.NewActionsHelper()
	err := helper.VerifyHeader(payload, sigHeader, testActionSecret)
	require.ErrorIs(t, err, workos.ErrWebhookNoValidSignature)
}

func TestActionsHelper_VerifyHeader_EmptyHeader(t *testing.T) {
	helper := workos.NewActionsHelper()
	err := helper.VerifyHeader(`{}`, "", testActionSecret)
	require.ErrorIs(t, err, workos.ErrWebhookNotSigned)
}

func TestActionsHelper_VerifyHeader_ExpiredTimestamp(t *testing.T) {
	payload := `{"type":"authentication"}`
	// 10 minutes ago, well beyond the 30s default tolerance.
	old := time.Now().Add(-10 * time.Minute)
	sigHeader := buildActionSigHeader(testActionSecret, payload, old)

	helper := workos.NewActionsHelper()
	err := helper.VerifyHeader(payload, sigHeader, testActionSecret)
	require.ErrorIs(t, err, workos.ErrWebhookOutsideTolerance)
}

func TestActionsHelper_ConstructAction(t *testing.T) {
	payload := `{"id":"action_01","event":"authentication_action.created","object":"event","created_at":"2024-01-01T00:00:00Z","data":{"type":"authentication","action_id":"action_123","user":{"email":"test@example.com"}}}`
	now := time.Now()
	sigHeader := buildActionSigHeader(testActionSecret, payload, now)

	helper := workos.NewActionsHelper()
	action, err := helper.ConstructAction(payload, sigHeader, testActionSecret)
	require.NoError(t, err)
	require.Equal(t, "action_01", action.ID)
	require.Equal(t, "authentication_action.created", action.Event)
	require.Equal(t, "event", action.Object)
	require.Equal(t, "authentication", action.Data["type"])
	require.Equal(t, "action_123", action.Data["action_id"])

	user, ok := action.Data["user"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "test@example.com", user["email"])
}

func TestActionsHelper_ConstructAction_InvalidJSON(t *testing.T) {
	payload := `not-valid-json`
	now := time.Now()
	sigHeader := buildActionSigHeader(testActionSecret, payload, now)

	helper := workos.NewActionsHelper()
	_, err := helper.ConstructAction(payload, sigHeader, testActionSecret)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse action payload")
}

func TestActionsHelper_SignResponse(t *testing.T) {
	helper := workos.NewActionsHelper()

	result, err := helper.SignResponse(
		workos.ActionTypeAuthentication,
		workos.ActionVerdictAllow,
		"",
		testActionSecret,
	)
	require.NoError(t, err)
	require.NotEmpty(t, result.Payload)
	require.NotEmpty(t, result.Sig)
	require.Contains(t, result.Sig, "t=")
	require.Contains(t, result.Sig, "v1=")

	// Decode the payload and verify its contents.
	decoded, err := base64.StdEncoding.DecodeString(result.Payload)
	require.NoError(t, err)

	var body map[string]interface{}
	err = json.Unmarshal(decoded, &body)
	require.NoError(t, err)
	require.Equal(t, "authentication", body["type"])
	require.Equal(t, "Allow", body["verdict"])
	require.Equal(t, "", body["error_message"])
}

func TestActionsHelper_SignResponse_Deny(t *testing.T) {
	helper := workos.NewActionsHelper()

	result, err := helper.SignResponse(
		workos.ActionTypeUserRegistration,
		workos.ActionVerdictDeny,
		"IP blocked",
		testActionSecret,
	)
	require.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(result.Payload)
	require.NoError(t, err)

	var body map[string]interface{}
	err = json.Unmarshal(decoded, &body)
	require.NoError(t, err)
	require.Equal(t, "user_registration", body["type"])
	require.Equal(t, "Deny", body["verdict"])
	require.Equal(t, "IP blocked", body["error_message"])
}

func TestActionsHelper_SignResponse_SignatureIsVerifiable(t *testing.T) {
	helper := workos.NewActionsHelper()

	result, err := helper.SignResponse(
		workos.ActionTypeAuthentication,
		workos.ActionVerdictAllow,
		"",
		testActionSecret,
	)
	require.NoError(t, err)

	// The signature produced by SignResponse should be verifiable by VerifyHeader.
	err = helper.VerifyHeader(result.Payload, result.Sig, testActionSecret)
	require.NoError(t, err)
}
