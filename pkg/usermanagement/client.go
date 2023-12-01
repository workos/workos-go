package usermanagement

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v3/internal/workos"
	"github.com/workos/workos-go/v3/pkg/common"
	"github.com/workos/workos-go/v3/pkg/mfa"
	"github.com/workos/workos-go/v3/pkg/workos_errors"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Order represents the order of records.
type Order string

// Constants that enumerate the available orders.
const (
	Asc  Order = "asc"
	Desc Order = "desc"
)

// InvitationState represents the state of an Invitation.
type InvitationState string

// Constants that enumerate the state of an Invitation.
const (
	Pending  InvitationState = "pending"
	Accepted InvitationState = "accepted"
	Expired  InvitationState = "expired"
	Revoked  InvitationState = "revoked"
)

type Invitation struct {
	ID             string          `json:"id"`
	Email          string          `json:"email"`
	State          InvitationState `json:"state"`
	AcceptedAt     string          `json:"accepted_at,omitempty"`
	RevokedAt      string          `json:"revoked_at,omitempty"`
	Token          string          `json:"token"`
	OrganizationID string          `json:"organization_id,omitempty"`
	ExpiresAt      string          `json:"expires_at"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
}

// Organization contains data about a particular Organization.
type Organization struct {
	// The Organization's unique identifier.
	ID string `json:"id"`

	// The Organization's name.
	Name string `json:"name"`
}

// OrganizationMembership contains data about a particular OrganizationMembership.
type OrganizationMembership struct {
	// The Organization Membership's unique identifier.
	ID string `json:"id"`

	// The ID of the User.
	UserID string `json:"user_id"`

	// The ID of the Organization.
	OrganizationID string `json:"organization_id"`

	// CreatedAt is the timestamp of when the OrganizationMembership was created.
	CreatedAt string `json:"created_at"`

	// UpdatedAt is the timestamp of when the OrganizationMembership was updated.
	UpdatedAt string `json:"updated_at"`
}

// User contains data about a particular User.
type User struct {

	// The User's unique identifier.
	ID string `json:"id"`

	// The User's first name.
	FirstName string `json:"first_name"`

	// The User's last name.
	LastName string `json:"last_name"`

	// The User's email.
	Email string `json:"email"`

	// The timestamp of when the User was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the User was updated.
	UpdatedAt string `json:"updated_at"`

	// Whether the User email is verified.
	EmailVerified bool `json:"email_verified"`
}

// GetUserOpts contains the options to pass in order to get a user profile.
type GetUserOpts struct {
	// User unique identifier
	User string `json:"id"`
}

// ListUsersResponse contains the response from the ListUsers call.
type ListUsersResponse struct {
	// List of Users
	Data []User `json:"data"`

	// Cursor to paginate through the list of Users
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type ListUsersOpts struct {
	// Filter Users by their email.
	Email string `url:"email,omitempty"`

	// Filter Users by the organization they are members of.
	OrganizationID string `url:"organization_id,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided User ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided User ID.
	After string `url:"after,omitempty"`
}

type CreateUserOpts struct {
	Email         string `json:"email"`
	Password      string `json:"password,omitempty"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// The algorithm originally used to hash the password.
type PasswordHashType string

// Constants that enumerate the available password hash types.
const (
	Bcrypt PasswordHashType = "bcrypt"
)

type UpdateUserOpts struct {
	User             string
	FirstName        string           `json:"first_name,omitempty"`
	LastName         string           `json:"last_name,omitempty"`
	EmailVerified    bool             `json:"email_verified,omitempty"`
	Password         string           `json:"password,omitempty"`
	PasswordHash     string           `json:"password_hash,omitempty"`
	PasswordHashType PasswordHashType `json:"password_hash_type,omitempty"`
}

type DeleteUserOpts struct {
	User string
}

type AuthenticateWithPasswordOpts struct {
	ClientID  string `json:"client_id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type AuthenticateWithCodeOpts struct {
	ClientID  string `json:"client_id"`
	Code      string `json:"code"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type AuthenticateWithMagicAuthOpts struct {
	ClientID string `json:"client_id"`
	Code     string `json:"code"`
	Email    string `json:"email"`

	// An authorization code used in a previous authenticate request that resulted in an existing user error response.
	// By specifying link_authorization_code, the Magic Auth authentication will link the credentials of the previous
	// authorization code with this user.
	LinkAuthorizationCode string `json:"link_authorization_code,omitempty"`
	IPAddress             string `json:"ip_address,omitempty"`
	UserAgent             string `json:"user_agent,omitempty"`
}

type AuthenticateWithTOTPOpts struct {
	ClientID                   string `json:"client_id"`
	Code                       string `json:"code"`
	IPAddress                  string `json:"ip_address,omitempty"`
	UserAgent                  string `json:"user_agent,omitempty"`
	PendingAuthenticationToken string `json:"pending_authentication_token"`
	AuthenticationChallengeID  string `json:"authentication_challenge_id"`
}

type AuthenticateWithEmailVerificationCodeOpts struct {
	ClientID                   string `json:"client_id"`
	Code                       string `json:"code"`
	PendingAuthenticationToken string `json:"pending_authentication_token"`
	IPAddress                  string `json:"ip_address,omitempty"`
	UserAgent                  string `json:"user_agent,omitempty"`
}

type AuthenticateWithOrganizationSelectionOpts struct {
	ClientID                   string `json:"client_id"`
	PendingAuthenticationToken string `json:"pending_authentication_token"`
	OrganizationID             string `json:"organization_id"`
	IPAddress                  string `json:"ip_address,omitempty"`
	UserAgent                  string `json:"user_agent,omitempty"`
}

type AuthenticateResponse struct {
	User User `json:"user"`

	// Which Organization the user is signing in to.
	// If the user is a member of multiple organizations, this is the organization the user selected
	// as part of the authentication flow.
	// If the user is a member of only one organization, this is that organization.
	// If the user is not a member of any organizations, this is null.
	OrganizationID string `json:"organization_id"`
}

type SendVerificationEmailOpts struct {
	// The unique ID of the User who will be sent a verification email.
	User string
}

type VerifyEmailOpts struct {
	// The unique ID of the User whose email address will be verified.
	User string
	// The verification code emailed to the user.
	Code string `json:"code"`
}

type SendPasswordResetEmailOpts struct {
	// The unique ID of the User whose email address will be verified.
	Email string `json:"email"`

	// The URL that will be linked to in the verification email.
	PasswordResetUrl string `json:"password_reset_url"`
}

type ResetPasswordOpts struct {
	// The verification token emailed to the user.
	Token string `json:"token"`

	// The new password to be set for the user.
	NewPassword string `json:"new_password"`
}

type UserResponse struct {
	User User `json:"user"`
}

type SendMagicAuthCodeOpts struct {
	// The email address the one-time code will be sent to.
	Email string `json:"email"`
}

type EnrollAuthFactorOpts struct {
	User       string
	Type       mfa.FactorType `json:"type"`
	TOTPIssuer string         `json:"totp_issuer,omitempty"`
	TOTPUser   string         `json:"totp_user,omitempty"`
}

type EnrollAuthFactorResponse struct {
	Factor    mfa.Factor    `json:"authentication_factor"`
	Challenge mfa.Challenge `json:"authentication_challenge"`
}

type ListAuthFactorsOpts struct {
	User string
}

type ListAuthFactorsResponse struct {
	Data []mfa.Factor `json:"data"`

	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type GetOrganizationMembershipOpts struct {
	// Organization Membership unique identifier
	OrganizationMembership string
}

type ListOrganizationMembershipsOpts struct {
	// Filter memberships by Organization ID.
	OrganizationID string `url:"organization_id,omitempty"`

	// Filter memberships by User ID.
	UserID string `url:"user_id,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided
	// Organization Membership ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided
	// Organization Membership ID.
	After string `url:"after,omitempty"`
}

type ListOrganizationMembershipsResponse struct {
	Data []OrganizationMembership `json:"data"`

	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type CreateOrganizationMembershipOpts struct {
	// The ID of the User to add as a member.
	UserID string `json:"user_id"`

	// The ID of the Organization in which to add the User as a member.
	OrganizationID string `json:"organization_id"`
}

type DeleteOrganizationMembershipOpts struct {
	// The ID of the Organization Membership to delete.
	OrganizationMembership string
}

type GetInvitationOpts struct {
	Invitation string
}

// ListInvitations contains the response from the ListInvitations call.
type ListInvitationsResponse struct {
	// List of Invitations
	Data []Invitation `json:"data"`

	// Cursor to paginate through the list of Invitations
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

type ListInvitationsOpts struct {
	OrganizationID string `json:"organization_id,omitempty"`

	Email string `json:"email,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided User ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided User ID.
	After string `url:"after,omitempty"`
}

type SendInvitationOpts struct {
	Email          string `json:"email"`
	OrganizationID string `json:"organization_id,omitempty"`
	ExpiresInDays  int    `json:"expires_in_days,omitempty"`
	InviterUserID  string `json:"inviter_user_id,omitempty"`
}

func NewClient(apiKey string) *Client {
	return &Client{
		APIKey:     apiKey,
		Endpoint:   "https://api.workos.com",
		HTTPClient: &http.Client{Timeout: time.Second * 10},
		JSONEncode: json.Marshal,
	}
}

// GetUser returns details of an existing user
func (c *Client) GetUser(ctx context.Context, opts GetUserOpts) (User, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users/%s",
		c.Endpoint,
		opts.User,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return User{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return User{}, err
	}

	var body User
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// ListUsers get a list of all of your existing users matching the criteria specified.
func (c *Client) ListUsers(ctx context.Context, opts ListUsersOpts) (ListUsersResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users",
		c.Endpoint,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListUsersResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	queryValues, err := query.Values(opts)
	if err != nil {
		return ListUsersResponse{}, err
	}

	req.URL.RawQuery = queryValues.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListUsersResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListUsersResponse{}, err
	}

	var body ListUsersResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// CreateUser create a new user with email password authentication.
// Only unmanaged users can be created directly using the User Management API.
func (c *Client) CreateUser(ctx context.Context, opts CreateUserOpts) (User, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users",
		c.Endpoint,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return User{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return User{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return User{}, err
	}

	var body User
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// UpdateUser updates User attributes.
func (c *Client) UpdateUser(ctx context.Context, opts UpdateUserOpts) (User, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users/%s",
		c.Endpoint,
		opts.User,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return User{}, err
	}

	req, err := http.NewRequest(
		http.MethodPut,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return User{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return User{}, err
	}

	var body User
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// DeleteUser delete an existing user.
func (c *Client) DeleteUser(ctx context.Context, opts DeleteUserOpts) error {
	endpoint := fmt.Sprintf(
		"%s/user_management/users/%s",
		c.Endpoint,
		opts.User,
	)

	req, err := http.NewRequest(
		http.MethodDelete,
		endpoint,
		nil,
	)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// AuthenticateWithPassword authenticates a user with Email and Password
func (c *Client) AuthenticateWithPassword(ctx context.Context, opts AuthenticateWithPasswordOpts) (AuthenticateResponse, error) {
	payload := struct {
		AuthenticateWithPasswordOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateWithPasswordOpts: opts,
		ClientSecret:                 c.APIKey,
		GrantType:                    "password",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticateResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/user_management/authenticate",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticateResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticateResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticateResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticateResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// AuthenticateWithCode authenticates an OAuth user or a managed SSO user that is logging in through SSO
func (c *Client) AuthenticateWithCode(ctx context.Context, opts AuthenticateWithCodeOpts) (AuthenticateResponse, error) {
	payload := struct {
		AuthenticateWithCodeOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateWithCodeOpts: opts,
		ClientSecret:             c.APIKey,
		GrantType:                "authorization_code",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticateResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/user_management/authenticate",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticateResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticateResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticateResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticateResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// AuthenticateWithMagicAuth authenticates a user by verifying a one-time code sent to the user's email address by
// the Magic Auth Send Code endpoint.
func (c *Client) AuthenticateWithMagicAuth(ctx context.Context, opts AuthenticateWithMagicAuthOpts) (AuthenticateResponse, error) {
	payload := struct {
		AuthenticateWithMagicAuthOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateWithMagicAuthOpts: opts,
		ClientSecret:                  c.APIKey,
		GrantType:                     "urn:workos:oauth:grant-type:magic-auth:code",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticateResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/user_management/authenticate",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticateResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticateResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticateResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticateResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// AuthenticateWithTOTP authenticates a user by verifying a time-based one-time password (TOTP)
func (c *Client) AuthenticateWithTOTP(ctx context.Context, opts AuthenticateWithTOTPOpts) (AuthenticateResponse, error) {
	payload := struct {
		AuthenticateWithTOTPOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateWithTOTPOpts: opts,
		ClientSecret:             c.APIKey,
		GrantType:                "workos:oauth:grant-type:mfa-totp",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticateResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/user_management/authenticate",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticateResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticateResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticateResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticateResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// AuthenticateWithEmailVerificationCode authenticates a user by verifying a code sent to their email address
func (c *Client) AuthenticateWithEmailVerificationCode(ctx context.Context, opts AuthenticateWithEmailVerificationCodeOpts) (AuthenticateResponse, error) {
	payload := struct {
		AuthenticateWithEmailVerificationCodeOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateWithEmailVerificationCodeOpts: opts,
		ClientSecret: c.APIKey,
		GrantType:    "urn:workos:oauth:grant-type:email-verification:code",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticateResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/user_management/authenticate",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticateResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticateResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticateResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticateResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// AuthenticateWithOrganizationSelection completes authentication for a user given an organization they've selected.
func (c *Client) AuthenticateWithOrganizationSelection(ctx context.Context, opts AuthenticateWithOrganizationSelectionOpts) (AuthenticateResponse, error) {
	payload := struct {
		AuthenticateWithOrganizationSelectionOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateWithOrganizationSelectionOpts: opts,
		ClientSecret: c.APIKey,
		GrantType:    "urn:workos:oauth:grant-type:organization-selection",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticateResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/user_management/authenticate",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticateResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticateResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticateResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticateResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// SendVerificationEmail creates an email verification challenge and emails verification token to user.
func (c *Client) SendVerificationEmail(ctx context.Context, opts SendVerificationEmailOpts) (UserResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users/%s/email_verification/send",
		c.Endpoint,
		opts.User,
	)
	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		nil,
	)
	if err != nil {
		return UserResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return UserResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return UserResponse{}, err
	}

	var body UserResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// VerifyEmail verifies a user's email using the verification token that was sent to the user.
func (c *Client) VerifyEmail(ctx context.Context, opts VerifyEmailOpts) (UserResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users/%s/email_verification/confirm",
		c.Endpoint,
		opts.User,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return UserResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return UserResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return UserResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return UserResponse{}, err
	}

	var body UserResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// SendPasswordResetEmail creates a password reset challenge and emails a password reset link to an
// unmanaged user.
func (c *Client) SendPasswordResetEmail(ctx context.Context, opts SendPasswordResetEmailOpts) error {
	endpoint := fmt.Sprintf(
		"%s/user_management/password_reset/send",
		c.Endpoint,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// ResetPassword resets user password using token that was sent to the user.
func (c *Client) ResetPassword(ctx context.Context, opts ResetPasswordOpts) (UserResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/password_reset/confirm",
		c.Endpoint,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return UserResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return UserResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return UserResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return UserResponse{}, err
	}

	var body UserResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// SendMagicAuthCode creates a one-time Magic Auth code and emails it to the user.
func (c *Client) SendMagicAuthCode(ctx context.Context, opts SendMagicAuthCodeOpts) error {
	endpoint := fmt.Sprintf(
		"%s/user_management/magic_auth/send",
		c.Endpoint,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// EnrollAuthFactor enrolls an authentication factor for the user.
func (c *Client) EnrollAuthFactor(ctx context.Context, opts EnrollAuthFactorOpts) (EnrollAuthFactorResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users/%s/auth_factors",
		c.Endpoint,
		opts.User,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return EnrollAuthFactorResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return EnrollAuthFactorResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return EnrollAuthFactorResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return EnrollAuthFactorResponse{}, err
	}

	var body EnrollAuthFactorResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// ListAuthFactors lists the available authentication factors for the user.
func (c *Client) ListAuthFactors(ctx context.Context, opts ListAuthFactorsOpts) (ListAuthFactorsResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/users/%s/auth_factors",
		c.Endpoint,
		opts.User,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListAuthFactorsResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListAuthFactorsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListAuthFactorsResponse{}, err
	}

	var body ListAuthFactorsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// GetOrganizationMembership returns details of an existing Organization Membership
func (c *Client) GetOrganizationMembership(ctx context.Context, opts GetOrganizationMembershipOpts) (OrganizationMembership, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/organization_memberships/%s",
		c.Endpoint,
		opts.OrganizationMembership,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return OrganizationMembership{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationMembership{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationMembership{}, err
	}

	var body OrganizationMembership
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// List Organization Memberships matching the criteria specified.
func (c *Client) ListOrganizationMemberships(ctx context.Context, opts ListOrganizationMembershipsOpts) (ListOrganizationMembershipsResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/organization_memberships",
		c.Endpoint,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListOrganizationMembershipsResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	queryValues, err := query.Values(opts)
	if err != nil {
		return ListOrganizationMembershipsResponse{}, err
	}

	req.URL.RawQuery = queryValues.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListOrganizationMembershipsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListOrganizationMembershipsResponse{}, err
	}

	var body ListOrganizationMembershipsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// Create an Organization Membership. Adds a User to an Organization.
func (c *Client) CreateOrganizationMembership(ctx context.Context, opts CreateOrganizationMembershipOpts) (OrganizationMembership, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/organization_memberships",
		c.Endpoint,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return OrganizationMembership{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return OrganizationMembership{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return OrganizationMembership{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return OrganizationMembership{}, err
	}

	var body OrganizationMembership
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// Delete an Organization Membership. Removes the membership's User from its Organization.
func (c *Client) DeleteOrganizationMembership(ctx context.Context, opts DeleteOrganizationMembershipOpts) error {
	endpoint := fmt.Sprintf(
		"%s/user_management/organization_memberships/%s",
		c.Endpoint,
		opts.OrganizationMembership,
	)

	req, err := http.NewRequest(
		http.MethodDelete,
		endpoint,
		nil,
	)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// GetInvitation fetches an Invitation by its ID.
func (c *Client) GetInvitation(ctx context.Context, opts GetInvitationOpts) (Invitation, error) {
	endpoint := fmt.Sprintf("%s/user_management/invitations/%s", c.Endpoint, opts.Invitation)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Invitation{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Invitation{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Invitation{}, err
	}

	var body Invitation
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// ListInvitations gets a list of all of your existing Invitations matching the criteria specified.
func (c *Client) ListInvitations(ctx context.Context, opts ListInvitationsOpts) (ListInvitationsResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/user_management/invitations",
		c.Endpoint,
	)

	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListInvitationsResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	queryValues, err := query.Values(opts)
	if err != nil {
		return ListInvitationsResponse{}, err
	}

	req.URL.RawQuery = queryValues.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListInvitationsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListInvitationsResponse{}, err
	}

	var body ListInvitationsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

func (c *Client) SendInvitation(ctx context.Context, opts SendInvitationOpts) (Invitation, error) {
	endpoint := fmt.Sprintf("%s/user_management/invitations", c.Endpoint)

	data, err := json.Marshal(opts)
	if err != nil {
		return Invitation{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return Invitation{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Invitation{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Invitation{}, err
	}

	var body Invitation
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}
