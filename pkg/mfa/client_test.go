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

func TestGetFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetFactorOpts
		expected Factor
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns a Factor",
			client: &Client{
				APIKey: "test",
			},
			options: GetFactorOpts{
				FactorID: "auth_factor_test123",
			},
			expected: Factor{
				ID:        "auth_factor_test123",
				CreatedAt: "2022-02-17T22:39:26.616Z",
				UpdatedAt: "2022-02-17T22:39:26.616Z",
				Type:      "generic_otp",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getFactorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organization, err := client.GetFactor(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organization)
		})
	}
}

func TestDeleteFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteFactorOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteFactorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.DeleteFactor(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestEnrollFactor(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  EnrollFactorOpts
		expected Factor
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
			options: EnrollFactorOpts{
				Type:       "totp",
				TOTPIssuer: "WorkOS",
				TOTPUser:   "some_user",
			},
			expected: Factor{
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
			options: EnrollFactorOpts{
				Type:        "sms",
				PhoneNumber: "0000000000",
			},
			expected: Factor{
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

	body, err := json.Marshal(Factor{
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
		options  ChallengeFactorOpts
		expected Challenge
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
			options: ChallengeFactorOpts{
				FactorID: "auth_factor_id",
			},
			expected: Challenge{
				ID:        "auth_challenge_test123",
				CreatedAt: "2022-02-17T22:39:26.616Z",
				UpdatedAt: "2022-02-17T22:39:26.616Z",
				FactorID:  "auth_factor_test123",
				ExpiresAt: "2022-02-17T22:39:26.616Z",
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

	body, err := json.Marshal(Challenge{
		ID:        "auth_challenge_test123",
		CreatedAt: "2022-02-17T22:39:26.616Z",
		UpdatedAt: "2022-02-17T22:39:26.616Z",
		FactorID:  "auth_factor_test123",
		ExpiresAt: "2022-02-17T22:39:26.616Z",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestVerifyChallenge(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifyChallengeOpts
		expected VerifyChallengeResponse
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
			options: VerifyChallengeOpts{
				ChallengeID: "auth_challenge_test123",
				Code:        "0000000",
			},
			expected: VerifyChallengeResponse{
				Valid: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(verifyChallengeTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.VerifyChallenge(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func getFactorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(Factor{
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

func deleteFactorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func verifyChallengeTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(VerifyChallengeResponse{
		Valid: true,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestVerifyChallengeError(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifyChallengeOpts
		expected VerificationResponseError
		err      bool
	}{
		{
			scenario: "Request returns response with totp",
			client: &Client{
				APIKey: "test",
			},
			options: VerifyChallengeOpts{
				ChallengeID: "auth_challenge_test123",
				Code:        "0000000",
			},
			expected: VerificationResponseError{
				Code:    "authentication_challenge_expired",
				Message: "The authentication challenge 'auth_challenge_1234' has expired.",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(verifyChallengeErrorTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			_, err := client.VerifyChallenge(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.Equal(t, test.expected.Error(), err.Error())
		})
	}
}

func verifyChallengeErrorTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(VerifyChallengeResponseError{
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
