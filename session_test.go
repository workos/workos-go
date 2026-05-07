// @oagen-ignore-file

package workos_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v8"
)

// testPassword is a valid 64-char hex string (decodes to 32 bytes).
const testPassword = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// otherPassword is a different valid 64-char hex string for negative tests.
const otherPassword = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func TestSealData_UnsealData_RoundTrip(t *testing.T) {
	password := testPassword
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
	password := testPassword
	data := map[string]interface{}{
		"secret": "value",
	}

	sealed, err := workos.SealData(data, password)
	require.NoError(t, err)

	_, err = workos.UnsealData(sealed, otherPassword)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt")
}

func TestSealData_RejectsShortPassword(t *testing.T) {
	data := map[string]interface{}{"key": "value"}
	_, err := workos.SealData(data, "too-short")
	require.Error(t, err)
	require.Contains(t, err.Error(), "64-character hex string")
}

func TestSealData_RejectsNonHexPassword(t *testing.T) {
	data := map[string]interface{}{"key": "value"}
	// 64 characters but not hex.
	notHex := "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	_, err := workos.SealData(data, notHex)
	require.Error(t, err)
	require.Contains(t, err.Error(), "valid hex string")
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
	password := testPassword
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
	password := testPassword
	data := map[string]interface{}{}

	sealed, err := workos.SealData(data, password)
	require.NoError(t, err)

	result, err := workos.UnsealData(sealed, password)
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestSealData_ProducesDifferentCiphertexts(t *testing.T) {
	password := testPassword
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
	_, err := workos.UnsealData("not-valid-base64!!!", testPassword)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode")
}

func TestUnsealData_TruncatedCiphertext(t *testing.T) {
	// Very short base64 that decodes to fewer bytes than a GCM nonce.
	_, err := workos.UnsealData("AQID", testPassword)
	require.Error(t, err)
}
