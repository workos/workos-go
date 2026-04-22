// @oagen-ignore-file

package workos

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCEPair holds a PKCE code verifier and challenge.
type PKCEPair struct {
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string // always "S256"
}

// GenerateCodeVerifier generates a cryptographically random PKCE code verifier.
// Length must be between 43 and 128 characters (default 43).
func GenerateCodeVerifier(length ...int) (string, error) {
	n := 43
	if len(length) > 0 {
		n = length[0]
	}
	if n < 43 || n > 128 {
		return "", fmt.Errorf("workos: PKCE code verifier length must be between 43 and 128, got %d", n)
	}

	// We need enough random bytes so that base64url encoding (without padding)
	// produces at least n characters. Each 3 bytes produces 4 base64 characters,
	// so we need ceil(n * 3 / 4) bytes.
	byteLen := (n*3 + 3) / 4
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("workos: failed to generate random bytes: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(buf)
	return encoded[:n], nil
}

// GenerateCodeChallenge computes the S256 code challenge for a given verifier.
func GenerateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GeneratePKCEPair generates a complete PKCE pair (verifier + challenge).
func GeneratePKCEPair() (*PKCEPair, error) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}
	challenge := GenerateCodeChallenge(verifier)
	return &PKCEPair{
		CodeVerifier:        verifier,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}, nil
}
