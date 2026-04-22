// @oagen-ignore-file

package workos_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v7"
)

func TestGenerateCodeVerifier_DefaultLength(t *testing.T) {
	verifier, err := workos.GenerateCodeVerifier()
	require.NoError(t, err)
	require.Len(t, verifier, 43)
}

func TestGenerateCodeVerifier_CustomLength(t *testing.T) {
	verifier, err := workos.GenerateCodeVerifier(128)
	require.NoError(t, err)
	require.Len(t, verifier, 128)
}

func TestGenerateCodeVerifier_TooShort(t *testing.T) {
	_, err := workos.GenerateCodeVerifier(10)
	require.Error(t, err)
	require.Contains(t, err.Error(), "between 43 and 128")
}

func TestGenerateCodeVerifier_TooLong(t *testing.T) {
	_, err := workos.GenerateCodeVerifier(200)
	require.Error(t, err)
	require.Contains(t, err.Error(), "between 43 and 128")
}

func TestGenerateCodeVerifier_Uniqueness(t *testing.T) {
	v1, err := workos.GenerateCodeVerifier()
	require.NoError(t, err)
	v2, err := workos.GenerateCodeVerifier()
	require.NoError(t, err)
	require.NotEqual(t, v1, v2, "two generated verifiers should not be equal")
}

func TestGenerateCodeChallenge_Deterministic(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := workos.GenerateCodeChallenge(verifier)

	// Compute expected S256 challenge manually.
	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	require.Equal(t, expected, challenge)

	// Calling again with the same verifier should produce the same result.
	challenge2 := workos.GenerateCodeChallenge(verifier)
	require.Equal(t, challenge, challenge2)
}

func TestGeneratePKCEPair(t *testing.T) {
	pair, err := workos.GeneratePKCEPair()
	require.NoError(t, err)
	require.NotNil(t, pair)

	require.Len(t, pair.CodeVerifier, 43)
	require.Equal(t, "S256", pair.CodeChallengeMethod)

	// Verify the challenge matches the verifier.
	expectedChallenge := workos.GenerateCodeChallenge(pair.CodeVerifier)
	require.Equal(t, expectedChallenge, pair.CodeChallenge)
}
