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
	opts EnrollFactorOpts,
) (Factor, error) {
	return DefaultClient.EnrollFactor(ctx, opts)
}

// ChallengeFactor Initiates the authentication process for the newly created MFA authorization factor.
func ChallengeFactor(
	ctx context.Context,
	opts ChallengeFactorOpts,
) (Challenge, error) {
	return DefaultClient.ChallengeFactor(ctx, opts)
}

// VerifyChallenge verifies the one time password provided by the end-user.
func VerifyChallenge(
	ctx context.Context,
	opts VerifyChallengeOpts,
) (VerifyChallengeResponse, error) {
	return DefaultClient.VerifyChallenge(ctx, opts)
}

// Deprecated: Use VerifyChallenge instead
func VerifyFactor(
	ctx context.Context,
	opts VerifyChallengeOpts,
) (interface{}, error) {
	return DefaultClient.VerifyFactor(ctx, opts)
}

// DeleteFactor deletes a factor by ID.
func DeleteFactor(
	ctx context.Context,
	opts DeleteFactorOpts,
) error {
	return DefaultClient.DeleteFactor(ctx, opts)
}

// GetFactor gets a factor by ID.
func GetFactor(
	ctx context.Context,
	opts GetFactorOpts,
) (Factor, error) {
	return DefaultClient.GetFactor(ctx, opts)
}
