// Package `usermanagement` provides a client wrapping the WorkOS User Management API.
package usermanagement

import (
	"context"
	"net/http"
)

var (
	// DefaultClient is the client used by User management methods
	DefaultClient = NewClient("")
)

// Client represents a client that fetch User Management data from WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	//
	// REQUIRED.
	APIKey string

	// The http.Client that is used to send request to WorkOS.
	//
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API.
	//
	// Defaults to https://api.workos.com.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)
}

// SetAPIKey configures the default client that is used by the User management methods
// It must be called before using those functions.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetUser gets a User.
func GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (User, error) {
	return DefaultClient.GetUser(ctx, opts)
}

// ListUsers gets a list of Users.
func ListUsers(
	ctx context.Context,
	opts ListUsersOpts,
) (ListUsersResponse, error) {
	return DefaultClient.ListUsers(ctx, opts)
}

// CreateUser creates a User.
func CreateUser(
	ctx context.Context,
	opts CreateUserOpts,
) (User, error) {
	return DefaultClient.CreateUser(ctx, opts)
}

// UpdateUser creates a User.
func UpdateUser(
	ctx context.Context,
	opts UpdateUserOpts,
) (User, error) {
	return DefaultClient.UpdateUser(ctx, opts)
}

// DeleteUser deletes a existing User.
func DeleteUser(
	ctx context.Context,
	opts DeleteUserOpts,
) error {
	return DefaultClient.DeleteUser(ctx, opts)
}

// AuthenticateWithPassword authenticates a user with email and password and optionally creates a session.
func AuthenticateWithPassword(
	ctx context.Context,
	opts AuthenticateWithPasswordOpts,
) (UserResponse, error) {
	return DefaultClient.AuthenticateWithPassword(ctx, opts)
}

// AuthenticateWithCode authenticates an OAuth user or a managed SSO user that is logging in through SSO, and
// optionally creates a session.
func AuthenticateWithCode(
	ctx context.Context,
	opts AuthenticateWithCodeOpts,
) (UserResponse, error) {
	return DefaultClient.AuthenticateWithCode(ctx, opts)
}

// AuthenticateWithMagicAuth authenticates a user by verifying a one-time code sent to the user's email address by
// the Magic Auth Send Code endpoint.
func AuthenticateWithMagicAuth(
	ctx context.Context,
	opts AuthenticateWithMagicAuthOpts,
) (UserResponse, error) {
	return DefaultClient.AuthenticateWithMagicAuth(ctx, opts)
}

// AuthenticateWithTOTP authenticates a user by verifying a time-based one-time password (TOTP)
func AuthenticateWithTOTP(
	ctx context.Context,
	opts AuthenticateWithTOTPOpts,
) (UserResponse, error) {
	return DefaultClient.AuthenticateWithTOTP(ctx, opts)
}

// SendVerificationEmail creates an email verification challenge and emails verification token to user.
func SendVerificationEmail(
	ctx context.Context,
	opts SendVerificationEmailOpts,
) (UserResponse, error) {
	return DefaultClient.SendVerificationEmail(ctx, opts)
}

// VerifyEmail verifies a user's email using the verification token that was sent to the user.
func VerifyEmail(
	ctx context.Context,
	opts VerifyEmailOpts,
) (UserResponse, error) {
	return DefaultClient.VerifyEmail(ctx, opts)
}

// SendPasswordResetEmail creates a password reset challenge and emails a password reset link to an unmanaged user.
func SendPasswordResetEmail(
	ctx context.Context,
	opts SendPasswordResetEmailOpts,
) (UserResponse, error) {
	return DefaultClient.SendPasswordResetEmail(ctx, opts)
}

// ResetPassword resets user password using token that was sent to the user.
func ResetPassword(
	ctx context.Context,
	opts ResetPasswordOpts,
) (UserResponse, error) {
	return DefaultClient.ResetPassword(ctx, opts)
}

// SendMagicAuthCode sends a one-time code to the user's email address.
func SendMagicAuthCode(
	ctx context.Context,
	opts SendMagicAuthCodeOpts,
) (UserResponse, error) {
	return DefaultClient.SendMagicAuthCode(ctx, opts)
}

// EnrollAuthFactor enrolls an authentication factor for the user.
func EnrollAuthFactor(
	ctx context.Context,
	opts EnrollAuthFactorOpts,
) (AuthenticationResponse, error) {
	return DefaultClient.EnrollAuthFactor(ctx, opts)
}

// ListAuthFactors lists the available authentication factors for the user.
func ListAuthFactors(
	ctx context.Context,
	opts ListAuthFactorsOpts,
) (ListAuthFactorsResponse, error) {
	return DefaultClient.ListAuthFactors(ctx, opts)
}
