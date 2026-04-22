// @oagen-ignore-file

package workos

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// VaultEncryptResult is the result of a Vault.Encrypt call.
type VaultEncryptResult struct {
	// EncryptedData is the base64-encoded ciphertext (LEB128 header + encrypted keys + nonce + AES-GCM output).
	EncryptedData string
	// KeyContext is the encryption key context used for this operation.
	KeyContext KeyContext
	// EncryptedKeys is the base64-encoded encrypted key blob for later decryption via the API.
	EncryptedKeys string
}

// Encrypt generates a data key and encrypts data locally using AES-256-GCM.
func (s *VaultService) Encrypt(ctx context.Context, data string, keyContext KeyContext, associatedData string, opts ...RequestOption) (*VaultEncryptResult, error) {
	keyPair, err := s.CreateDataKey(ctx, &VaultCreateDataKeyParams{
		Context: keyContext,
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("workos: vault encrypt: failed to create data key: %w", err)
	}

	encrypted, err := LocalEncrypt(data, *keyPair, associatedData)
	if err != nil {
		return nil, fmt.Errorf("workos: vault encrypt: %w", err)
	}

	return &VaultEncryptResult{
		EncryptedData: encrypted,
		KeyContext:    keyPair.Context,
		EncryptedKeys: keyPair.EncryptedKeys,
	}, nil
}

// Decrypt decrypts locally encrypted data by first decrypting the data key via the API.
func (s *VaultService) Decrypt(ctx context.Context, encryptedData string, associatedData string, opts ...RequestOption) (string, error) {
	// Parse the encrypted data to extract the encrypted keys and context.
	raw, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("workos: vault decrypt: failed to base64-decode encrypted data: %w", err)
	}

	keysLen, bytesRead, err := decodeLEB128(raw)
	if err != nil {
		return "", fmt.Errorf("workos: vault decrypt: failed to decode LEB128 prefix: %w", err)
	}

	if uint32(len(raw)-bytesRead) < keysLen {
		return "", errors.New("workos: vault decrypt: encrypted data too short for declared key length")
	}

	encryptedKeysBytes := raw[bytesRead : bytesRead+int(keysLen)]
	encryptedKeysB64 := base64.StdEncoding.EncodeToString(encryptedKeysBytes)

	// Decrypt the data key via the API. We pass an empty KeyContext here;
	// the server will derive the context from the encrypted keys blob.
	dataKey, err := s.DecryptDataKey(ctx, &VaultDecryptDataKeyParams{
		EncryptedKeys: encryptedKeysB64,
	}, opts...)
	if err != nil {
		return "", fmt.Errorf("workos: vault decrypt: failed to decrypt data key: %w", err)
	}

	plaintext, err := LocalDecrypt(encryptedData, *dataKey, associatedData)
	if err != nil {
		return "", fmt.Errorf("workos: vault decrypt: %w", err)
	}

	return plaintext, nil
}

// LocalEncrypt encrypts data with AES-256-GCM using a pre-fetched data key pair.
//
// Wire format (before base64): LEB128(len(encryptedKeys)) || encryptedKeys || nonce(12) || ciphertext+tag
func LocalEncrypt(data string, keyPair DataKeyPair, associatedData string) (string, error) {
	// Decode the raw AES key.
	rawKey, err := base64.StdEncoding.DecodeString(keyPair.DataKey.Key)
	if err != nil {
		return "", fmt.Errorf("failed to decode data key: %w", err)
	}

	// Decode the encrypted keys blob.
	encryptedKeys, err := base64.StdEncoding.DecodeString(keyPair.EncryptedKeys)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted keys: %w", err)
	}

	// Create AES-GCM cipher.
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce.
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt.
	ciphertext := gcm.Seal(nil, nonce, []byte(data), []byte(associatedData))

	// Build output: LEB128(len(encryptedKeys)) || encryptedKeys || nonce || ciphertext+tag
	prefix := encodeLEB128(uint32(len(encryptedKeys)))
	buf := make([]byte, 0, len(prefix)+len(encryptedKeys)+len(nonce)+len(ciphertext))
	buf = append(buf, prefix...)
	buf = append(buf, encryptedKeys...)
	buf = append(buf, nonce...)
	buf = append(buf, ciphertext...)

	return base64.StdEncoding.EncodeToString(buf), nil
}

// LocalDecrypt decrypts data with AES-256-GCM using a pre-fetched data key.
func LocalDecrypt(encryptedData string, dataKey DataKey, associatedData string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to base64-decode encrypted data: %w", err)
	}

	// Parse LEB128 length prefix to skip the encrypted keys.
	keysLen, bytesRead, err := decodeLEB128(raw)
	if err != nil {
		return "", fmt.Errorf("failed to decode LEB128 prefix: %w", err)
	}

	offset := bytesRead + int(keysLen)
	if offset+12 > len(raw) {
		return "", errors.New("encrypted data too short: missing nonce")
	}

	// Extract nonce (12 bytes) and ciphertext+tag (remainder).
	nonce := raw[offset : offset+12]
	ciphertext := raw[offset+12:]

	if len(ciphertext) == 0 {
		return "", errors.New("encrypted data too short: missing ciphertext")
	}

	// Decode the raw AES key.
	rawKey, err := base64.StdEncoding.DecodeString(dataKey.Key)
	if err != nil {
		return "", fmt.Errorf("failed to decode data key: %w", err)
	}

	// AES-GCM decrypt.
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(associatedData))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// encodeLEB128 encodes a uint32 as an unsigned LEB128 byte sequence.
func encodeLEB128(n uint32) []byte {
	if n == 0 {
		return []byte{0}
	}
	var buf []byte
	for n > 0 {
		b := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			b |= 0x80
		}
		buf = append(buf, b)
	}
	return buf
}

// decodeLEB128 decodes an unsigned LEB128 value from the start of buf.
// It returns the decoded value, the number of bytes consumed, and any error.
func decodeLEB128(buf []byte) (uint32, int, error) {
	var result uint32
	var shift uint
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i + 1, nil
		}
		shift += 7
		if shift >= 35 {
			return 0, 0, errors.New("LEB128 value too large for uint32")
		}
	}
	return 0, 0, errors.New("unexpected end of LEB128 data")
}
