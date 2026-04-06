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

// SealData encrypts data using AES-256-GCM with the provided password.
// The password should be a hex-encoded 32-byte key. If the password is not
// valid hex or not the right length, it is hashed with SHA-256 to derive a key.
// Returns a base64-encoded sealed string.
func SealData(data map[string]interface{}, password string) (string, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("workos: failed to marshal data: %w", err)
	}

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

// UnsealData decrypts a sealed string back to the original data.
func UnsealData(sealed string, password string) (map[string]interface{}, error) {
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

	var result map[string]interface{}
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, fmt.Errorf("workos: failed to unmarshal decrypted data: %w", err)
	}
	return result, nil
}

// deriveKey derives a 32-byte AES key from the password.
// If the password is a valid hex-encoded 32-byte string (64 hex chars), it is decoded directly.
// Otherwise, the password is hashed with SHA-256.
func deriveKey(password string) ([]byte, error) {
	decoded, err := hex.DecodeString(password)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	hash := sha256.Sum256([]byte(password))
	return hash[:], nil
}
