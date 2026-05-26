// @oagen-ignore-file

package workos_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v8"
)

func makeTestDataKeyPair() workos.CreateDataKeyResponse {
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}
	b64Key := base64.StdEncoding.EncodeToString(rawKey)
	encryptedKeys := base64.StdEncoding.EncodeToString([]byte("fake-encrypted-keys"))

	return workos.CreateDataKeyResponse{
		DataKey:       b64Key,
		EncryptedKeys: encryptedKeys,
	}
}

func TestLocalEncryptDecrypt_RoundTrip(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "hello, vault encryption!"

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	require.NotEqual(t, plaintext, encrypted)

	decrypted, err := workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: pair.DataKey}, "")
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestLocalEncryptDecrypt_WithAssociatedData(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "sensitive data"
	associatedData := "context-info"

	encrypted, err := workos.LocalEncrypt(plaintext, pair, associatedData)
	require.NoError(t, err)

	decrypted, err := workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: pair.DataKey}, associatedData)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	_, err = workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: pair.DataKey}, "wrong-context")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt")
}

func TestLocalEncryptDecrypt_EmptyString(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := ""

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	decrypted, err := workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: pair.DataKey}, "")
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestLocalEncryptDecrypt_LargeData(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := ""
	for i := 0; i < 10000; i++ {
		plaintext += "a"
	}

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	decrypted, err := workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: pair.DataKey}, "")
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestLocalDecrypt_FailsWithWrongKey(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "secret message"

	encrypted, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 100)
	}
	wrongB64Key := base64.StdEncoding.EncodeToString(wrongKey)

	_, err = workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: wrongB64Key}, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt")
}

func TestLocalDecrypt_FailsWithInvalidBase64(t *testing.T) {
	_, err := workos.LocalDecrypt("not-valid-base64!!!", workos.DecryptResponse{DataKey: ""}, "")
	require.Error(t, err)
}

func TestLocalEncrypt_ProducesDifferentCiphertexts(t *testing.T) {
	pair := makeTestDataKeyPair()
	plaintext := "same input twice"

	encrypted1, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	encrypted2, err := workos.LocalEncrypt(plaintext, pair, "")
	require.NoError(t, err)

	require.NotEqual(t, encrypted1, encrypted2)

	decrypted1, err := workos.LocalDecrypt(encrypted1, workos.DecryptResponse{DataKey: pair.DataKey}, "")
	require.NoError(t, err)

	decrypted2, err := workos.LocalDecrypt(encrypted2, workos.DecryptResponse{DataKey: pair.DataKey}, "")
	require.NoError(t, err)

	require.Equal(t, decrypted1, decrypted2)
	require.Equal(t, plaintext, decrypted1)
}
