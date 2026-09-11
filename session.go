// @oagen-ignore-file

package workos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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
// The password should be a 64-character hex string encoding 32 random bytes
// (e.g. generated with openssl rand -hex 32). Otherwise, it must be at least
// 32 characters and is hashed with SHA-256 to derive a key. Shorter passwords
// are rejected with an error.
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
// The password should be a 64-character hex string encoding 32 random bytes
// (e.g. generated with openssl rand -hex 32). Otherwise, it must be at least
// 32 characters and is hashed with SHA-256 to derive a key. Shorter passwords
// are rejected with an error.
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
// If the password is a valid hex-encoded 32-byte string (64 hex chars), it is
// decoded directly. Otherwise, the password must be at least 32 characters and
// is hashed with SHA-256 exactly as before, so existing cookies sealed under
// compliant passwords remain valid. Empty and short passwords are rejected
// to guard against session forgery with known or easily guessed keys.
func deriveKey(password string) ([]byte, error) {
	decoded, err := hex.DecodeString(password)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	if len(password) < 32 {
		return nil, fmt.Errorf("workos: cookie password must be at least 32 characters")
	}

	hash := sha256.Sum256([]byte(password))
	return hash[:], nil
}
