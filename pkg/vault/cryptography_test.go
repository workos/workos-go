package vault

import (
	"github.com/stretchr/testify/require"
	"math/rand/v2"
	"testing"
)

func TestEncodeU32(t *testing.T) {
	expected := []byte{141, 194, 2}
	res := EncodeU32(41229)
	require.Equal(t, expected, res)
}

func TestDecodeU32(t *testing.T) {
	buf := []byte{141, 194, 2}
	res, index, err := DecodeU32(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(41229), res)
	require.Equal(t, 3, index)

	buf = []byte{141, 194, 2, 4, 4, 4}
	res, index, err = DecodeU32(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(41229), res)
	require.Equal(t, 3, index)
}

func TestEncodingVarInts(t *testing.T) {
	for i := 0; i <= 10; i++ {
		int := rand.Uint32()
		buf := EncodeU32(int)
		res, _, err := DecodeU32(buf)
		require.NoError(t, err)
		require.Equal(t, int, res)
	}
}

// Test decryption of a known ciphertext and encryption key.
func TestLocalDecrypt(t *testing.T) {
	ciphertext := "hp2N0+hNnd4fYJikRre/1FtNE77Nn4Zi1q781iDv2dq5zpsMyXo1VT8UF2PC2NdXzgFXT1MuRUtNLnYxADAyMDVlMGVjLTgyOGUtNTU5NC05NmFjLWE2OGZjODI1N2ZiNwEBMQEkY2YyOWU2OGEtZjMyZC00MjhhLTk0ODYtNjliMDIzYmY2NTI0AXRjZjI5ZTY4YS1mMzJkLTQyOGEtOTQ4Ni02OWIwMjNiZjY1MjS5Fed5aLiPyIk3i9glB8ZYlUOGTeiCRmZR1rznsYoY+Cd6jTHD4zs7lOD9nVZt889z4LmdxSmPWwfPktRpTq5LIA7jx/gJ2krd2fpSMStFQ5ai/gJ1h2aXp46PyHNJ"
	encryptedKey := "V09TLkVLTS52MQAwMjA1ZTBlYy04MjhlLTU1OTQtOTZhYy1hNjhmYzgyNTdmYjcBATEBJGNmMjllNjhhLWYzMmQtNDI4YS05NDg2LTY5YjAyM2JmNjUyNAF0Y2YyOWU2OGEtZjMyZC00MjhhLTk0ODYtNjliMDIzYmY2NTI0uRXneWi4j8iJN4vYJQfGWJVDhk3ogkZmUda857GKGPgneo0xw+M7O5Tg/Z1WbfPPc+C5ncUpj1sHz5LUaU6uSyAO48f4CdpK3dn6UjErRUM="
	dataKey := DataKey{
		Key: "hNjAWl++MJjDZ64dUeYlgJZDEbemRmdKvNHUnnRFUNg=",
		Id:  "0205e0ec-828e-5594-96ac-a68fc8257fb7",
	}

	expected := "secret api key"
	iv := []byte{134, 157, 141, 211, 232, 77, 157, 222, 31, 96, 152, 164, 70, 183, 191, 212, 91, 77, 19, 190, 205, 159, 134, 98, 214, 174, 252, 214, 32, 239, 217, 218}
	authTag := []byte{185, 206, 155, 12, 201, 122, 53, 85, 63, 20, 23, 99, 194, 216, 215, 87}

	decoded, err := Decode(ciphertext)
	require.NoError(t, err)
	require.Equal(t, encryptedKey, decoded.Keys)
	require.Equal(t, iv, decoded.Iv)
	require.Equal(t, authTag, decoded.Tag)

	plaintext, err := LocalDecrypt(decoded, dataKey)
	require.NoError(t, err)
	require.Equal(t, expected, plaintext)
}

func TestLocalEncryptAndDecrypt(t *testing.T) {
	keyPair := DataKeyPair{
		DataKey:       "hNjAWl++MJjDZ64dUeYlgJZDEbemRmdKvNHUnnRFUNg=",
		Id:            "0205e0ec-828e-5594-96ac-a68fc8257fb7",
		EncryptedKeys: "V09TLkVLTS52MQAwMjA1ZTBlYy04MjhlLTU1OTQtOTZhYy1hNjhmYzgyNTdmYjcBATEBJGNmMjllNjhhLWYzMmQtNDI4YS05NDg2LTY5YjAyM2JmNjUyNAF0Y2YyOWU2OGEtZjMyZC00MjhhLTk0ODYtNjliMDIzYmY2NTI0uRXneWi4j8iJN4vYJQfGWJVDhk3ogkZmUda857GKGPgneo0xw+M7O5Tg/Z1WbfPPc+C5ncUpj1sHz5LUaU6uSyAO48f4CdpK3dn6UjErRUM=",
	}
	data := "super secret access codes"

	ciphertext, err := LocalEncrypt(data, keyPair)
	require.NoError(t, err)

	decoded, err := Decode(ciphertext)
	require.NoError(t, err)

	plaintext, err := LocalDecrypt(decoded, DataKey{Id: keyPair.Id, Key: keyPair.DataKey})
	require.NoError(t, err)
	require.Equal(t, data, plaintext)
}
