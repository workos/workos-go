// @oagen-ignore-file

package workos_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v10"
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

func TestLocalDecrypt_RejectsInvalidLengths(t *testing.T) {
	pair := makeTestDataKeyPair()
	tests := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{"empty prefix", nil, "unexpected end of LEB128 data"},
		{"truncated prefix", []byte{0x80}, "unexpected end of LEB128 data"},
		{"missing keys", []byte{0x01}, "encrypted data too short: missing nonce"},
		{"short nonce", make([]byte, 12), "encrypted data too short: missing nonce"},
		{"missing ciphertext", make([]byte, 13), "encrypted data too short: missing ciphertext"},
		{"max int32", []byte{0xff, 0xff, 0xff, 0xff, 0x07}, "encrypted data too short: missing nonce"},
		{"above max int32", []byte{0x80, 0x80, 0x80, 0x80, 0x08}, "encrypted data too short: missing nonce"},
		{"max uint32", []byte{0xff, 0xff, 0xff, 0xff, 0x0f}, "encrypted data too short: missing nonce"},
		{"above max uint32", []byte{0x80, 0x80, 0x80, 0x80, 0x10}, "LEB128 value too large for uint32"},
		{"overflow with low bits", []byte{0xff, 0xff, 0xff, 0xff, 0x1f}, "LEB128 value too large for uint32"},
		{"max fifth byte payload", []byte{0xff, 0xff, 0xff, 0xff, 0x7f}, "LEB128 value too large for uint32"},
		{"fifth byte continuation", []byte{0x80, 0x80, 0x80, 0x80, 0x80}, "LEB128 value too large for uint32"},
		{"six byte prefix", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, "LEB128 value too large for uint32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := base64.StdEncoding.EncodeToString(tt.raw)
			require.NotPanics(t, func() {
				plaintext, err := workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: pair.DataKey}, "")
				require.ErrorContains(t, err, tt.wantErr)
				require.Empty(t, plaintext)
			})
		})
	}
}

func TestLocalEncryptDecrypt_MultiByteKeyLength(t *testing.T) {
	pair := makeTestDataKeyPair()
	pair.EncryptedKeys = base64.StdEncoding.EncodeToString(make([]byte, 128))

	encrypted, err := workos.LocalEncrypt("hello, vault encryption!", pair, "")
	require.NoError(t, err)

	decrypted, err := workos.LocalDecrypt(encrypted, workos.DecryptResponse{DataKey: pair.DataKey}, "")
	require.NoError(t, err)
	require.Equal(t, "hello, vault encryption!", decrypted)
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
