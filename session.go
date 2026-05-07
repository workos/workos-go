// @oagen-ignore-file

package workos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// sealBytes encrypts plaintext bytes using AES-256-GCM with the provided password.
// Returns a base64-encoded sealed string.
func sealBytes(plaintext []byte, password string) (string, error) {
	key, err := deriveKey(password)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("workos: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("workos: failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("workos: failed to generate nonce: %w", err)
	}

	// Seal appends the ciphertext (with GCM tag) to nonce.
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(sealed), nil
}

// unsealToBytes decrypts a sealed string back to raw plaintext bytes.
func unsealToBytes(sealed string, password string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to decode sealed data: %w", err)
	}

	key, err := deriveKey(password)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("workos: sealed data too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertextBody := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextBody, nil)
	if err != nil {
		return nil, fmt.Errorf("workos: failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// Seal encrypts data of any JSON-serializable type using AES-256-GCM.
// The password MUST be a 64-character hex string that decodes to exactly
// 32 bytes (256 bits). Anything else returns an error. Generate a suitable
// value with `openssl rand -hex 32` and store it as a secret.
// Returns a base64-encoded sealed string.
func Seal[T any](data T, password string) (string, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("workos: failed to marshal data: %w", err)
	}
	return sealBytes(plaintext, password)
}

// Unseal decrypts a sealed string back to the original typed data.
func Unseal[T any](sealed, password string) (T, error) {
	var zero T
	plaintext, err := unsealToBytes(sealed, password)
	if err != nil {
		return zero, err
	}
	var result T
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return zero, fmt.Errorf("workos: failed to unmarshal decrypted data: %w", err)
	}
	return result, nil
}

// SealData encrypts data using AES-256-GCM with the provided password.
// Deprecated: Use Seal instead.
func SealData(data map[string]interface{}, password string) (string, error) {
	return Seal(data, password)
}

// UnsealData decrypts a sealed string back to the original data.
// Deprecated: Use Unseal instead.
func UnsealData(sealed string, password string) (map[string]interface{}, error) {
	return Unseal[map[string]interface{}](sealed, password)
}

// SealSession encrypts a SessionData struct using AES-256-GCM.
// Returns a base64-encoded sealed string suitable for use as a session cookie.
func SealSession(data *SessionData, password string) (string, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("workos: failed to marshal session data: %w", err)
	}
	return sealBytes(plaintext, password)
}

// unsealSession decrypts a sealed string directly into a SessionData struct.
func unsealSession(sealed string, password string) (*SessionData, error) {
	plaintext, err := unsealToBytes(sealed, password)
	if err != nil {
		return nil, err
	}

	var session SessionData
	if err := json.Unmarshal(plaintext, &session); err != nil {
		return nil, fmt.Errorf("workos: failed to unmarshal session data: %w", err)
	}
	return &session, nil
}

// deriveKey derives a 32-byte AES key from the password.
//
// The password MUST be a 64-character lowercase or uppercase hex string that
// decodes to exactly 32 bytes (256 bits) of high-entropy key material.
// Anything else is rejected with an error. Generate a suitable value with
// `openssl rand -hex 32` (or any cryptographically secure equivalent) and
// store it as a secret.
//
// Note: this is a strict-mode change. Earlier versions silently accepted any
// password by hashing it with SHA-256, which gave a misleading sense of
// security for short or low-entropy values. Short passwords now error at
// SDK init / first call rather than producing a weak key.
func deriveKey(password string) ([]byte, error) {
	if len(password) != 64 {
		return nil, fmt.Errorf("workos: cookie password must be a 64-character hex string (32 bytes); got length %d", len(password))
	}
	decoded, err := hex.DecodeString(password)
	if err != nil {
		return nil, fmt.Errorf("workos: cookie password must be a valid hex string: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("workos: cookie password must decode to exactly 32 bytes; got %d", len(decoded))
	}
	return decoded, nil
}
