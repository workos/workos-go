package mfa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnrollFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetEnrollOpts
		expected EnrollResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns response with totp",
			client: &Client{
				APIKey: "test",
			},
			options: GetEnrollOpts{
				Type:       "totp",
				TotpIssuer: "WorkOS",
				TotpUser:   "some_user",
			},
			expected: EnrollResponse{
				ID:        "auth_factor_test123",
				CreatedAt: "2022-02-17T22:39:26.616Z",
				UpdatedAt: "2022-02-17T22:39:26.616Z",
				Type:      "generic_otp",
			},
		},
		{
			scenario: "Request returns response with sms",
			client: &Client{
				APIKey: "test",
			},
			options: GetEnrollOpts{
				Type:        "sms",
				PhoneNumber: "0000000000",
			},
			expected: EnrollResponse{
				ID:        "auth_factor_test123",
				CreatedAt: "2022-02-17T22:39:26.616Z",
				UpdatedAt: "2022-02-17T22:39:26.616Z",
				Type:      "generic_otp",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(enrollFactorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.EnrollFactor(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func enrollFactorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(EnrollResponse{
		ID:        "auth_factor_test123",
		CreatedAt: "2022-02-17T22:39:26.616Z",
		UpdatedAt: "2022-02-17T22:39:26.616Z",
		Type:      "generic_otp",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestChallengeFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ChallengeOpts
		expected ChallengeResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns response with totp",
			client: &Client{
				APIKey: "test",
			},
			options: ChallengeOpts{
				AuthenticationFactorID: "auth_factor_id",
			},
			expected: ChallengeResponse{
				ID:                     "auth_challenge_test123",
				CreatedAt:              "2022-02-17T22:39:26.616Z",
				UpdatedAt:              "2022-02-17T22:39:26.616Z",
				AuthenticationFactorID: "auth_factor_test123",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(challengeFactorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.ChallengeFactor(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func challengeFactorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(ChallengeResponse{
		ID:                     "auth_challenge_test123",
		CreatedAt:              "2022-02-17T22:39:26.616Z",
		UpdatedAt:              "2022-02-17T22:39:26.616Z",
		AuthenticationFactorID: "auth_factor_test123",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestVerifyFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifyOpts
		expected VerifyResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns response with totp",
			client: &Client{
				APIKey: "test",
			},
			options: VerifyOpts{
				AuthenticationChallengeID: "auth_challenge_test123",
				Code:                      "0000000",
			},
			expected: VerifyResponse{
				Valid: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(verifyFactorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.VerifyFactor(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func verifyFactorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(VerifyResponse{
		Valid: true,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestVerifyFactorError(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifyOpts
		expected VerifyResponseError
		err      bool
	}{
		{
			scenario: "Request returns response with totp",
			client: &Client{
				APIKey: "test",
			},
			options: VerifyOpts{
				AuthenticationChallengeID: "auth_challenge_test123",
				Code:                      "0000000",
			},
			expected: VerifyResponseError{
				Code:    "authentication_challenge_expired",
				Message: "The authentication challenge 'auth_challenge_1234' has expired.",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(verifyFactorErrorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.VerifyFactor(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func verifyFactorErrorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(VerifyResponseError{
		Code:    "authentication_challenge_expired",
		Message: "The authentication challenge 'auth_challenge_1234' has expired.",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
