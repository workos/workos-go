// @oagen-ignore-file

package workos_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v10"
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
	timestamp := strconv.FormatInt(ts.UnixMilli(), 10)
	sig := computeTestActionSignature(secret, timestamp, payload)
	return fmt.Sprintf("t=%s,v1=%s", timestamp, sig)
}

func marshalWithoutHTMLEscaping(t *testing.T, value interface{}) string {
	t.Helper()
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	require.NoError(t, encoder.Encode(value))
	return string(bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}))
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
	timestamp := strconv.FormatInt(now.UnixMilli(), 10)
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
	old := time.Now().Add(-10 * time.Minute)
	sigHeader := buildActionSigHeader(testActionSecret, payload, old)

	helper := workos.NewActionsHelper()
	err := helper.VerifyHeader(payload, sigHeader, testActionSecret)
	require.ErrorIs(t, err, workos.ErrWebhookOutsideTolerance)
}

func TestActionsHelper_ConstructAuthenticationAction(t *testing.T) {
	payload := `{"object":"authentication_action_context","id":"action_01","authentication_method":"Password","user":{"object":"user","id":"user_01","email":"test@example.com"},"organization":{"object":"organization","id":"org_01","name":"Example","domains":[],"metadata":{},"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"},"ip_address":"203.0.113.1","user_agent":"Mozilla/5.0","device_fingerprint":"fingerprint","issuer":"client_01"}`
	sigHeader := buildActionSigHeader(testActionSecret, payload, time.Now())

	action, err := workos.NewActionsHelper().ConstructAction(payload, sigHeader, testActionSecret)
	require.NoError(t, err)
	require.Equal(t, "authentication_action_context", action.Object)
	require.Equal(t, "action_01", action.ID)
	require.Equal(t, workos.AuthenticateResponseAuthenticationMethodPassword, action.AuthenticationMethod)
	require.Equal(t, "test@example.com", action.User.Email)
	require.Equal(t, "Example", action.Organization.Name)
	require.Equal(t, "203.0.113.1", action.IPAddress)
	require.Equal(t, "client_01", action.Issuer)
}

func TestActionsHelper_ConstructUserRegistrationAction(t *testing.T) {
	payload := `{"object":"user_registration_action_context","id":"action_01","authentication_method":"GoogleOAuth","user_data":{"object":"user_data","email":"test@example.com","name":null,"first_name":"Test","last_name":"User"},"invitation":{"object":"invitation","id":"invitation_01","email":"test@example.com","expires_at":"2024-01-02T00:00:00Z","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"},"ip_address":"203.0.113.1"}`
	sigHeader := buildActionSigHeader(testActionSecret, payload, time.Now())

	action, err := workos.NewActionsHelper().ConstructAction(payload, sigHeader, testActionSecret)
	require.NoError(t, err)
	require.Equal(t, "user_registration_action_context", action.Object)
	require.Equal(t, workos.AuthenticateResponseAuthenticationMethodGoogleOAuth, action.AuthenticationMethod)
	require.Equal(t, "test@example.com", action.UserData.Email)
	require.Equal(t, "Test", action.UserData.FirstName)
	require.Equal(t, "invitation_01", action.Invitation.ID)
}

func TestActionsHelper_ConstructAction_InvalidPayload(t *testing.T) {
	helper := workos.NewActionsHelper()

	invalidJSON := `not-valid-json`
	_, err := helper.ConstructAction(invalidJSON, buildActionSigHeader(testActionSecret, invalidJSON, time.Now()), testActionSecret)
	require.ErrorContains(t, err, "failed to parse action payload")

	unsupported := `{"object":"event","id":"event_01"}`
	_, err = helper.ConstructAction(unsupported, buildActionSigHeader(testActionSecret, unsupported, time.Now()), testActionSecret)
	require.ErrorContains(t, err, `unsupported action object "event"`)
}

func TestActionsHelper_SignResponse(t *testing.T) {
	response, err := workos.NewActionsHelper().SignResponse(
		workos.ActionTypeAuthentication,
		workos.ActionVerdictAllow,
		"",
		testActionSecret,
	)
	require.NoError(t, err)
	require.Equal(t, "authentication_action_response", response.Object)
	require.Equal(t, workos.ActionVerdictAllow, response.Payload.Verdict)
	require.Empty(t, response.Payload.ErrorMessage)

	timestamp := strconv.FormatInt(response.Payload.Timestamp, 10)
	expected := computeTestActionSignature(testActionSecret, timestamp, marshalWithoutHTMLEscaping(t, response.Payload))
	require.Equal(t, expected, response.Signature)

	body, err := json.Marshal(response)
	require.NoError(t, err)
	require.JSONEq(t, fmt.Sprintf(`{"object":"authentication_action_response","payload":{"timestamp":%s,"verdict":"Allow"},"signature":"%s"}`, timestamp, expected), string(body))
}

func TestActionsHelper_SignResponse_Deny(t *testing.T) {
	response, err := workos.NewActionsHelper().SignResponse(
		workos.ActionTypeUserRegistration,
		workos.ActionVerdictDeny,
		"Email must not contain <script>",
		testActionSecret,
	)
	require.NoError(t, err)
	require.Equal(t, "user_registration_action_response", response.Object)
	require.Equal(t, "Email must not contain <script>", response.Payload.ErrorMessage)

	timestamp := strconv.FormatInt(response.Payload.Timestamp, 10)
	expected := computeTestActionSignature(testActionSecret, timestamp, marshalWithoutHTMLEscaping(t, response.Payload))
	require.Equal(t, expected, response.Signature)
}

func TestActionsHelper_SignResponse_InvalidInput(t *testing.T) {
	helper := workos.NewActionsHelper()

	_, err := helper.SignResponse(workos.ActionType("unknown"), workos.ActionVerdictAllow, "", testActionSecret)
	require.ErrorContains(t, err, `unsupported action type "unknown"`)

	_, err = helper.SignResponse(workos.ActionTypeAuthentication, workos.ActionVerdict("unknown"), "", testActionSecret)
	require.ErrorContains(t, err, `unsupported action verdict "unknown"`)
}
