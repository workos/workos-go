package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type EncryptOpts struct {
	Data       string
	KeyContext KeyContext
}

type DecryptOpts struct {
	Data string
}

type Decoded struct {
	Iv         []byte
	Tag        []byte
	Keys       string
	Ciphertext []byte
}

// LocalEncrypt performs a local encryption option.
func LocalEncrypt(
	data string,
	keyPair DataKeyPair,
) (string, error) {
	// Decode the plaintext data key
	dataKey, err := base64.StdEncoding.DecodeString(keyPair.DataKey)
	if err != nil {
		return "", err
	}

	// Decode the encrypted key
	keyBlob, err := base64.StdEncoding.DecodeString(keyPair.EncryptedKeys)
	if err != nil {
		return "", err
	}

	prefixLen := EncodeU32(uint32(len(keyBlob)))

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 32)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 32)
	rand.Read(iv)

	ciphertext := aesgcm.Seal(nil, iv, []byte(data), nil)
	ciphertextLen := len(ciphertext) - 16
	authTag := ciphertext[ciphertextLen:]
	payload := append(iv, authTag[:]...)
	payload = append(payload, prefixLen[:]...)
	payload = append(payload, keyBlob[:]...)
	payload = append(payload, ciphertext[:ciphertextLen]...)

	return base64.StdEncoding.EncodeToString(payload), nil
}

// LocalDecrypt perfroms a local decryption of data that was previously encrypted with Vault.
func LocalDecrypt(
	decoded Decoded,
	dataKey DataKey,
) (string, error) {
	key, err := base64.StdEncoding.DecodeString(dataKey.Key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 32)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, decoded.Iv, append(decoded.Ciphertext, decoded.Tag[:]...), nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Decode parses an encrypted blob into its parts without attempting to decrypt it.
func Decode(data string) (Decoded, error) {
	payload, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return Decoded{}, err
	}

	iv := payload[0:32]
	tag := payload[32:48]
	keyLen, lebLen, err := DecodeU32(payload[48:])
	if err != nil {
		return Decoded{}, err
	}

	keysIndex := 48 + lebLen
	keysEnd := keysIndex + int(keyLen)
	keys := base64.StdEncoding.EncodeToString(payload[keysIndex:keysEnd])
	ciphertext := payload[keysEnd:]

	return Decoded{
		Iv:         iv,
		Tag:        tag,
		Keys:       keys,
		Ciphertext: ciphertext,
	}, nil
}

// EncodeU64 converts num to a leb128 encoded array of bytes
func EncodeU32(num uint32) []byte {
	buf := make([]byte, 0)

	done := false
	for !done {
		b := byte(num & 0x7F)

		num = num >> 7
		if num == 0 {
			done = true
		} else {
			b |= 0x80
		}

		buf = append(buf, b)
	}

	return buf
}

// DecodeU32 converts a leb128 byte array to a uint32.
func DecodeU32(buf []byte) (uint32, int, error) {
	var res uint32

	bit := int8(0)
	for i, b := range buf {
		if i > 4 {
			return 0, 0, errors.New("LEB128 integer overflow (was more than 4 bytes)")
		}

		res |= uint32(b&0x7f) << (7 * bit)

		signBit := b & 0x80
		if signBit == 0 {
			return res, i + 1, nil
		}

		bit++
	}

	return 0, 0, errors.New("LEB128 integer not found")
}
