package mfa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMfaEnrollFactors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(enrollFactorTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := AuthenticationFactor{
		ID:        "auth_factor_test123",
		CreatedAt: "2022-02-17T22:39:26.616Z",
		UpdatedAt: "2022-02-17T22:39:26.616Z",
		Type:      "generic_otp",
	}
	AuthenticationFactor, err := EnrollFactor(context.Background(), EnrollFactorOpts{
		Type:       "totp",
		TOTPIssuer: "WorkOS",
		TOTPUser:   "some_user",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, AuthenticationFactor)
}

func TestMfaChallengeFactors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(challengeFactorTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Challenge{
		ID:                     "auth_challenge_test123",
		CreatedAt:              "2022-02-17T22:39:26.616Z",
		UpdatedAt:              "2022-02-17T22:39:26.616Z",
		AuthenticationFactorID: "auth_factor_test123",
		ExpiresAt:              "2022-02-17T22:39:26.616Z",
	}
	Challenge, err := ChallengeFactor(context.Background(), ChallengeOpts{
		AuthenticationFactorID: "auth_factor_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, Challenge)
}

func TestVerifyChallenges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(verifyChallengeTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := VerifyResponse{
		Valid: true,
	}
	verifyResponse, err := VerifyChallenge(context.Background(), VerifyChallengeOpts{
		AuthenticationChallengeID: "auth_challenge_test123",
		Code:                      "0000000",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, verifyResponse)
}

func TestGetFactors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getFactorTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := AuthenticationFactor{
		ID:        "auth_factor_test123",
		CreatedAt: "2022-02-17T22:39:26.616Z",
		UpdatedAt: "2022-02-17T22:39:26.616Z",
		Type:      "generic_otp",
	}
	factorResponse, err := GetFactor(context.Background(), GetFactorOpts{
		AuthenticationFactorID: "auth_factor_test123",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, factorResponse)
}

func TestDeleteFactors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteFactorTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteFactor(
		context.Background(),
		DeleteFactorOpts{
			AuthenticationFactorID: "auth_factor_test1231",
		},
	)

	require.NoError(t, err)
}
