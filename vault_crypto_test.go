// @oagen-ignore-file

package workos_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v7"
)

func makeTestDataKeyPair() workos.DataKeyPair {
	// Create a known 32-byte key, base64 encode it
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}
	b64Key := base64.StdEncoding.EncodeToString(rawKey)
	encryptedKeys := base64.StdEncoding.EncodeToString([]byte("fake-encrypted-keys"))

	return workos.DataKeyPair{
		DataKey:       workos.DataKey{Key: b64Key},
		EncryptedKeys: encryptedKeys,
	}
}

func TestLocalEncryptDecrypt_RoundTrip(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "hello, vault encryption!"

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	// The encrypted output should be base64-encoded and different from plaintext
	require.NotEqual(t, plaintext, encrypted)

	// Decrypt using the same key
	decrypted, err := workos.LocalDecrypt(encrypted, pair.DataKey, "")
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestLocalEncryptDecrypt_WithAssociatedData(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "sensitive data"
	associatedData := "context-info"

	encrypted, err := workos.LocalEncrypt(plaintext, pair, associatedData)
	require.NoError(t, err)

	// Decrypt with the same associated data should succeed
	decrypted, err := workos.LocalDecrypt(encrypted, pair.DataKey, associatedData)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	// Decrypt with different associated data should fail
	_, err = workos.LocalDecrypt(encrypted, pair.DataKey, "wrong-context")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt")
}

func TestLocalEncryptDecrypt_EmptyString(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := ""

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	decrypted, err := workos.LocalDecrypt(encrypted, pair.DataKey, "")
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestLocalEncryptDecrypt_LargeData(t *testing.T) {
	pair := makeTestDataKeyPair()
	// Create a 10KB plaintext
	plaintext := ""
	for i := 0; i < 10000; i++ {
		plaintext += "a"
	}

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	decrypted, err := workos.LocalDecrypt(encrypted, pair.DataKey, "")
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestLocalDecrypt_FailsWithWrongKey(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "secret message"

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	// Create a different key
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 100) // different key bytes
	}
	wrongB64Key := base64.StdEncoding.EncodeToString(wrongKey)

	wrongDataKey := workos.DataKey{Key: wrongB64Key}

	_, err = workos.LocalDecrypt(encrypted, wrongDataKey, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt")
}

func TestLocalDecrypt_FailsWithInvalidBase64(t *testing.T) {
	pair := makeTestDataKeyPair()

	_, err := workos.LocalDecrypt("not-valid-base64!!!", pair.DataKey, "")
	require.Error(t, err)
}

func TestLocalEncrypt_ProducesDifferentCiphertexts(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "same input twice"

	encrypted1, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	encrypted2, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	// Due to random nonce, encrypting the same data twice should produce different ciphertexts
	require.NotEqual(t, encrypted1, encrypted2)

	// But both should decrypt to the same plaintext
	decrypted1, err := workos.LocalDecrypt(encrypted1, pair.DataKey, "")
	require.NoError(t, err)

	decrypted2, err := workos.LocalDecrypt(encrypted2, pair.DataKey, "")
	require.NoError(t, err)

	require.Equal(t, decrypted1, decrypted2)
	require.Equal(t, plaintext, decrypted1)
}
