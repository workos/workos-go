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

	expectedResponse := EnrollResponse{
		ID:        "auth_factor_test123",
		CreatedAt: "2022-02-17T22:39:26.616Z",
		UpdatedAt: "2022-02-17T22:39:26.616Z",
		Type:      "generic_otp",
	}
	enrollResponse, err := EnrollFactor(context.Background(), GetEnrollOpts{
		Type:       "totp",
		TotpIssuer: "WorkOS",
		TotpUser:   "some_user",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, enrollResponse)
}

func TestMfaChallengeFactors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(challengeFactorTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ChallengeResponse{
		ID:                     "auth_challenge_test123",
		CreatedAt:              "2022-02-17T22:39:26.616Z",
		UpdatedAt:              "2022-02-17T22:39:26.616Z",
		AuthenticationFactorID: "auth_factor_test123",
		ExpiresAt:              "2022-02-17T22:39:26.616Z",
	}
	challengeResponse, err := ChallengeFactor(context.Background(), ChallengeOpts{
		AuthenticationFactorID: "auth_factor_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, challengeResponse)
}

func TestVerifyFactors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(verifyFactorTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := VerifyResponse{
		Valid: true,
	}
	verifyResponse, err := VerifyFactor(context.Background(), VerifyOpts{
		AuthenticationChallengeID: "auth_challenge_test123",
		Code:                      "0000000",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, verifyResponse)
}
