package mfa

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and mfa functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for mfa requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// EnrollFactor creates a MFA authorization factor.
func EnrollFactor(
	ctx context.Context,
	opts GetEnrollOpts,
) (EnrollResponse, error) {
	return DefaultClient.EnrollFactor(ctx, opts)
}

// ChallengeFactor Initiates the authentication process for the newly created MFA authorization factor.
func ChallengeFactor(
	ctx context.Context,
	opts ChallengeOpts,
) (ChallengeResponse, error) {
	return DefaultClient.ChallengeFactor(ctx, opts)
}

// VerifyChallenge verifies the one time password provided by the end-user.
func VerifyChallenge(
	ctx context.Context,
	opts VerifyOpts,
) (interface{}, error) {
	return DefaultClient.VerifyChallenge(ctx, opts)
}

// Deprecated: Use VerifyChallenge instead
func VerifyFactor(
	ctx context.Context,
	opts VerifyOpts,
) (interface{}, error) {
	return DefaultClient.VerifyFactor(ctx, opts)
}
