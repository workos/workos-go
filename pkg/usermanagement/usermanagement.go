// Package `usermanagement` provides a client wrapping the WorkOS User Management API.
package usermanagement

import (
	"context"
	"net/http"
	"net/url"
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

// GetUser gets a User.
func GetUserByExternalID(
	ctx context.Context,
	opts GetUserByExternalIDOpts,
) (User, error) {
	return DefaultClient.GetUserByExternalID(ctx, opts)
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

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func GetAuthorizationURL(opts GetAuthorizationURLOpts) (*url.URL, error) {
	return DefaultClient.GetAuthorizationURL(opts)
}

// AuthenticateWithPassword authenticates a user with email and password
func AuthenticateWithPassword(
	ctx context.Context,
	opts AuthenticateWithPasswordOpts,
) (AuthenticateResponse, error) {
	return DefaultClient.AuthenticateWithPassword(ctx, opts)
}

// AuthenticateWithCode authenticates an OAuth user or a managed SSO user that is logging in through SSO
func AuthenticateWithCode(
	ctx context.Context,
	opts AuthenticateWithCodeOpts,
) (AuthenticateResponse, error) {
	return DefaultClient.AuthenticateWithCode(ctx, opts)
}

// AuthenticateWithRefreshToken obtains a new AccessToken and RefreshToken for
// an existing session
func AuthenticateWithRefreshToken(
	ctx context.Context,
	opts AuthenticateWithRefreshTokenOpts,
) (RefreshAuthenticationResponse, error) {
	return DefaultClient.AuthenticateWithRefreshToken(ctx, opts)
}

// AuthenticateWithMagicAuth authenticates a user by verifying a one-time code sent to the user's email address by
// the Magic Auth Send Code endpoint.
func AuthenticateWithMagicAuth(
	ctx context.Context,
	opts AuthenticateWithMagicAuthOpts,
) (AuthenticateResponse, error) {
	return DefaultClient.AuthenticateWithMagicAuth(ctx, opts)
}

// AuthenticateWithTOTP authenticates a user by verifying a time-based one-time password (TOTP)
func AuthenticateWithTOTP(
	ctx context.Context,
	opts AuthenticateWithTOTPOpts,
) (AuthenticateResponse, error) {
	return DefaultClient.AuthenticateWithTOTP(ctx, opts)
}

// AuthenticateWithEmailVerificationCode authenticates a user by verifying an code sent to their email address.
func AuthenticateWithEmailVerificationCode(
	ctx context.Context,
	opts AuthenticateWithEmailVerificationCodeOpts,
) (AuthenticateResponse, error) {
	return DefaultClient.AuthenticateWithEmailVerificationCode(ctx, opts)
}

// AuthenticateWithOrganizationSelection completes authentication for a user given an organization they've selected.
func AuthenticateWithOrganizationSelection(
	ctx context.Context,
	opts AuthenticateWithOrganizationSelectionOpts,
) (AuthenticateResponse, error) {
	return DefaultClient.AuthenticateWithOrganizationSelection(ctx, opts)
}

// GetEmailVerification fetches an EmailVerification object by its ID.
func GetEmailVerification(
	ctx context.Context,
	opts GetEmailVerificationOpts,
) (EmailVerification, error) {
	return DefaultClient.GetEmailVerification(ctx, opts)
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

// GetPasswordReset fetches a Password Reset object by its ID.
func GetPasswordReset(
	ctx context.Context,
	opts GetPasswordResetOpts,
) (PasswordReset, error) {
	return DefaultClient.GetPasswordReset(ctx, opts)
}

// CreatePasswordReset creates a password reset token that can be sent to the user's email address and used to reset the password.
func CreatePasswordReset(
	ctx context.Context,
	opts CreatePasswordResetOpts,
) (PasswordReset, error) {
	return DefaultClient.CreatePasswordReset(ctx, opts)
}

// Deprecated: Use CreatePasswordReset instead. This method will be removed in a future major version.
func SendPasswordResetEmail(
	ctx context.Context,
	opts SendPasswordResetEmailOpts,
) error {
	return DefaultClient.SendPasswordResetEmail(ctx, opts)
}

// ResetPassword resets user password using token that was sent to the user.
func ResetPassword(
	ctx context.Context,
	opts ResetPasswordOpts,
) (UserResponse, error) {
	return DefaultClient.ResetPassword(ctx, opts)
}

// GetMagicAuth fetches a Magic Auth object by its ID.
func GetMagicAuth(
	ctx context.Context,
	opts GetMagicAuthOpts,
) (MagicAuth, error) {
	return DefaultClient.GetMagicAuth(ctx, opts)
}

// CreateMagicAuth creates a one-time code that can be sent to the user's email address and used for authentication.
func CreateMagicAuth(
	ctx context.Context,
	opts CreateMagicAuthOpts,
) (MagicAuth, error) {
	return DefaultClient.CreateMagicAuth(ctx, opts)
}

// Deprecated: Use CreateMagicAuth instead. This method will be removed in a future major version.
func SendMagicAuthCode(
	ctx context.Context,
	opts SendMagicAuthCodeOpts,
) error {
	return DefaultClient.SendMagicAuthCode(ctx, opts)
}

// EnrollAuthFactor enrolls an authentication factor for the user.
func EnrollAuthFactor(
	ctx context.Context,
	opts EnrollAuthFactorOpts,
) (EnrollAuthFactorResponse, error) {
	return DefaultClient.EnrollAuthFactor(ctx, opts)
}

// ListAuthFactors lists the available authentication factors for the user.
func ListAuthFactors(
	ctx context.Context,
	opts ListAuthFactorsOpts,
) (ListAuthFactorsResponse, error) {
	return DefaultClient.ListAuthFactors(ctx, opts)
}

// GetOrganizationMembership gets an OrganizationMembership.
func GetOrganizationMembership(
	ctx context.Context,
	opts GetOrganizationMembershipOpts,
) (OrganizationMembership, error) {
	return DefaultClient.GetOrganizationMembership(ctx, opts)
}

// ListOrganizationMemberships gets a list of OrganizationMemberhips.
func ListOrganizationMemberships(
	ctx context.Context,
	opts ListOrganizationMembershipsOpts,
) (ListOrganizationMembershipsResponse, error) {
	return DefaultClient.ListOrganizationMemberships(ctx, opts)
}

// CreateOrganizationMembership creates an OrganizationMembership.
func CreateOrganizationMembership(
	ctx context.Context,
	opts CreateOrganizationMembershipOpts,
) (OrganizationMembership, error) {
	return DefaultClient.CreateOrganizationMembership(ctx, opts)
}

// UpdateOrganizationMembership updates an OrganizationMembership.
func UpdateOrganizationMembership(
	ctx context.Context,
	organizationMembershipId string,
	opts UpdateOrganizationMembershipOpts,
) (OrganizationMembership, error) {
	return DefaultClient.UpdateOrganizationMembership(ctx, organizationMembershipId, opts)
}

// DeleteOrganizationMembership deletes an existing OrganizationMembership.
func DeleteOrganizationMembership(
	ctx context.Context,
	opts DeleteOrganizationMembershipOpts,
) error {
	return DefaultClient.DeleteOrganizationMembership(ctx, opts)
}

// DeactivateOrganizationMembership deactivates an OrganizationMembership.
func DeactivateOrganizationMembership(
	ctx context.Context,
	opts DeactivateOrganizationMembershipOpts,
) (OrganizationMembership, error) {
	return DefaultClient.DeactivateOrganizationMembership(ctx, opts)
}

// ReactivateOrganizationMembership reactivates an OrganizationMembership.
func ReactivateOrganizationMembership(
	ctx context.Context,
	opts ReactivateOrganizationMembershipOpts,
) (OrganizationMembership, error) {
	return DefaultClient.ReactivateOrganizationMembership(ctx, opts)
}

func GetInvitation(
	ctx context.Context,
	opts GetInvitationOpts,
) (Invitation, error) {
	return DefaultClient.GetInvitation(ctx, opts)
}

func FindInvitationByToken(
	ctx context.Context,
	opts FindInvitationByTokenOpts,
) (Invitation, error) {
	return DefaultClient.FindInvitationByToken(ctx, opts)
}

func ListInvitations(
	ctx context.Context,
	opts ListInvitationsOpts,
) (ListInvitationsResponse, error) {
	return DefaultClient.ListInvitations(ctx, opts)
}

func SendInvitation(
	ctx context.Context,
	opts SendInvitationOpts,
) (Invitation, error) {
	return DefaultClient.SendInvitation(ctx, opts)
}

func RevokeInvitation(
	ctx context.Context,
	opts RevokeInvitationOpts,
) (Invitation, error) {
	return DefaultClient.RevokeInvitation(ctx, opts)
}

func GetJWKSURL(clientID string) (*url.URL, error) {
	return DefaultClient.GetJWKSURL(clientID)
}

func GetLogoutURL(opts GetLogoutURLOpts) (*url.URL, error) {
	return DefaultClient.GetLogoutURL(opts)
}

func RevokeSession(ctx context.Context, opts RevokeSessionOpts) error {
	return DefaultClient.RevokeSession(ctx, opts)
}
