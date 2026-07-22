// @oagen-ignore-file

package workos_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v9"
)

func TestSealData_UnsealData_RoundTrip(t *testing.T) {
	password := "my-super-secret-password"
	data := map[string]interface{}{
		"user_id": "user_123",
		"email":   "test@example.com",
		"active":  true,
	}

	sealed, err := workos.SealData(data, password)
	require.NoError(t, err)
	require.NotEmpty(t, sealed)

	result, err := workos.UnsealData(sealed, password)
	require.NoError(t, err)
	require.Equal(t, "user_123", result["user_id"])
	require.Equal(t, "test@example.com", result["email"])
	require.Equal(t, true, result["active"])
}

func TestUnsealData_WrongPassword(t *testing.T) {
	password := "correct-password"
	data := map[string]interface{}{
		"secret": "value",
	}

	sealed, err := workos.SealData(data, password)
	require.NoError(t, err)

	_, err = workos.UnsealData(sealed, "wrong-password")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt")
}

func TestSealData_HexKey(t *testing.T) {
	// A valid 64-character hex string (32 bytes decoded).
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	data := map[string]interface{}{
		"key": "value",
	}

	sealed, err := workos.SealData(data, hexKey)
	require.NoError(t, err)

	result, err := workos.UnsealData(sealed, hexKey)
	require.NoError(t, err)
	require.Equal(t, "value", result["key"])
}

func TestSealData_NestedData(t *testing.T) {
	password := "test-password"
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "Alice",
			"roles": []interface{}{"admin", "editor"},
		},
		"count": float64(42),
	}

	sealed, err := workos.SealData(data, password)
	require.NoError(t, err)

	result, err := workos.UnsealData(sealed, password)
	require.NoError(t, err)

	user, ok := result["user"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "Alice", user["name"])

	roles, ok := user["roles"].([]interface{})
	require.True(t, ok)
	require.Len(t, roles, 2)
	require.Equal(t, "admin", roles[0])
	require.Equal(t, "editor", roles[1])

	require.Equal(t, float64(42), result["count"])
}

func TestSealData_EmptyMap(t *testing.T) {
	password := "test-password"
	data := map[string]interface{}{}

	sealed, err := workos.SealData(data, password)
	require.NoError(t, err)

	result, err := workos.UnsealData(sealed, password)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestSealData_ProducesDifferentCiphertexts(t *testing.T) {
	password := "test-password"
	data := map[string]interface{}{"key": "value"}

	sealed1, err := workos.SealData(data, password)
	require.NoError(t, err)

	sealed2, err := workos.SealData(data, password)
	require.NoError(t, err)

	// Due to random nonces, the ciphertexts should differ.
	require.NotEqual(t, sealed1, sealed2)

	// But both should decrypt to the same data.
	r1, err := workos.UnsealData(sealed1, password)
	require.NoError(t, err)
	r2, err := workos.UnsealData(sealed2, password)
	require.NoError(t, err)
	require.Equal(t, r1, r2)
}

func TestUnsealData_InvalidBase64(t *testing.T) {
	_, err := workos.UnsealData("not-valid-base64!!!", "password")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode")
}

func TestUnsealData_TruncatedCiphertext(t *testing.T) {
	// Very short base64 that decodes to fewer bytes than a GCM nonce.
	_, err := workos.UnsealData("AQID", "password")
	require.Error(t, err)
}

// TestSeal_EmptyPasswordRejected guards against SEC-1221: an empty cookie
// password derives the fixed, publicly known key SHA-256(""), which would let
// anyone forge session cookies. Sealing with an empty password must error.
func TestSeal_EmptyPasswordRejected(t *testing.T) {
	_, err := workos.SealData(map[string]interface{}{"a": "b"}, "")
	require.Error(t, err)

	_, err = workos.SealSession(&workos.SessionData{AccessToken: "x"}, "")
	require.Error(t, err)
}

// TestAuthenticateSession_EmptyPasswordRejected guards against SEC-1221: an
// attacker who knows the victim app uses an empty cookie password can forge a
// cookie under the fixed, publicly known key SHA-256(""). Authentication with
// an empty password must not succeed.
func TestAuthenticateSession_EmptyPasswordRejected(t *testing.T) {
	// hex(SHA-256("")) — the fixed 32-byte key the pre-patch deriveKey produced
	// for an empty password. deriveKey accepts a 64-char hex string as a raw
	// key, so sealing under this value yields exactly the cookie an attacker
	// could forge (offline, with no secret) to target an app misconfigured with
	// an empty cookie password.
	const emptyPasswordKeyHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	forged, err := workos.SealSession(&workos.SessionData{AccessToken: "x"}, emptyPasswordKeyHex)
	require.NoError(t, err)

	// Before the fix, AuthenticateSession(forged, "") derived the same
	// SHA-256("") key, unsealed the forged cookie, and returned it. It must now
	// be rejected outright.
	result, err := workos.AuthenticateSession(forged, "")
	require.NoError(t, err)
	require.False(t, result.Authenticated)
	require.Equal(t, "invalid_session_cookie", result.Reason)
}
