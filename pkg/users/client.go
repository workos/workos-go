package users

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v2/internal/workos"
	"github.com/workos/workos-go/v2/pkg/common"
	"github.com/workos/workos-go/v2/pkg/workos_errors"
	"net/http"
	"time"
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

// UserType represents the type of the User
type UserType string

// Constants that enumerate the UserType
const (
	Unmanaged UserType = "unmanaged"
	Managed   UserType = "managed"
)

// Organization contains data about a particular Organization.
type Organization struct {
	// The Organization's unique identifier.
	ID string `json:"id"`

	// The Organization's name.
	Name string `json:"name"`
}

// OrganizationMembership contains data about a particular OrganizationMembership.
type OrganizationMembership struct {
	// Contains the ID and name of the associated Organization.
	Organization Organization `json:"organization"`

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

	// The type of the User: `managed` or `unmanaged`
	UserType UserType `json:"user_type"`

	// The ID of the SSO Profile. Only managed users have SSO Profiles.
	SSOProfileID string `json:"sso_profile_id"`

	// The timestamp when the user's email was verified.
	// Email verification is only applicable to unmanaged users.
	EmailVerifiedAt string `json:"email_verified_at"`

	// The ID of the Google OAuth Profile.
	// Only unmanaged users who sign in with Google OAuth have Google OAuth Profiles.
	GoogleOAuthProfileID string `json:"google_oauth_profile_id"`
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
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

type ListUsersOpts struct {
	// Filter Users by their type.
	Type UserType `url:"type,omitempty"`

	// Filter Users by their email.
	Email string `url:"email,omitempty"`

	// Filter Users by the organization they are members of.
	Organization string `url:"organization,omitempty"`

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

type AuthorizedOrganization struct {
	Organization Organization `json:"organization"`
}
type Session struct {
	ID                        string                     `json:"id"`
	Token                     string                     `json:"token"`
	CreatedAt                 string                     `json:"created_at"`
	ExpiresAt                 string                     `json:"expires_at"`
	AuthorizedOrganizations   []AuthorizedOrganization   `json:"authorized_organizations"`
	UnauthorizedOrganizations []UnauthorizedOrganization `json:"unauthorized_organizations"`
}

type SessionAuthenticationMethod string

const (
	GoogleOauth    SessionAuthenticationMethod = "GoogleOauth"
	MagicAuth      SessionAuthenticationMethod = "MagicAuth"
	MicrosoftOauth SessionAuthenticationMethod = "MicrosoftOauth"
	Password       SessionAuthenticationMethod = "Password"
)

type UnauthorizedOrganizationReason struct {
	Type                         string                        `json:"type"`
	AllowedAuthenticationMethods []SessionAuthenticationMethod `json:"allowed_authentication_methods"`
}

type UnauthorizedOrganization struct {
	Organization Organization                     `json:"organization"`
	Reasons      []UnauthorizedOrganizationReason `json:"reasons"`
}

type AuthenticateUserWithPasswordOpts struct {
	ClientID  string `json:"client_id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
}

type AuthenticateUserWithTokenOpts struct {
	ClientID  string `json:"client_id"`
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type MagicAuthChallengeID string

type AuthenticateUserWithMagicAuthOpts struct {
	ClientID             string               `json:"client_id"`
	Code                 string               `json:"code"`
	MagicAuthChallengeID MagicAuthChallengeID `json:"magic_auth_challenge_id"`
	ExpiresIn            int                  `json:"expires_in,omitempty"`
	IPAddress            string               `json:"ip_address,omitempty"`
	UserAgent            string               `json:"user_agent,omitempty"`
}

type AuthenticationResponse struct {
	Session Session `json:"session"`
	User    User    `json:"user"`
}

type CreateEmailVerificationChallengeOpts struct {
	// The unique ID of the User whose email address will be verified.
	User string `json:"id"`

	// The URL that will be linked to in the verification email.
	VerificationUrl string `json:"verification_url"`
}

type CompleteEmailVerificationOpts struct {
	// The verification token emailed to the user.
	Token string `json:"token"`
}

type CreatePasswordResetChallengeOpts struct {
	// The unique ID of the User whose email address will be verified.
	Email string `json:"email"`

	// The URL that will be linked to in the verification email.
	PasswordResetUrl string `json:"password_reset_url"`
}

type CompletePasswordResetOpts struct {
	// The verification token emailed to the user.
	Token string `json:"token"`

	// The new password to be set for the user.
	NewPassword string `json:"new_password"`
}

type ChallengeResponse struct {
	Token string `json:"token"`

	User User `json:"user"`
}

type SendMagicAuthCodeOpts struct {
	// The email address the one-time code will be sent to.
	Email string `json:"email_address"`
}

type MagicAuthChallenge struct {
	MagicAuthChallengeID MagicAuthChallengeID `json:"id"`
}

type VerifySessionOpts struct {
	Token    string `json:"token"`
	ClientID string `json:"client_id"`
}

type VerifySessionResponse struct {
	Session Session `json:"session"`
	User    User    `json:"user"`
}

type RevokeSessionOpts struct {
	SessionToken string `json:"session_token,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
}

type RevokeAllSessionsForUserOpts struct {
	User string
}

type AddUserToOrganizationOpts struct {
	User         string `json:"id"`
	Organization string `json:"organization_id"`
}

type RemoveUserFromOrganizationOpts struct {
	User         string `json:"id"`
	Organization string `json:"organization_id"`
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
		"%s/users/%s",
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
		"%s/users",
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
		"%s/users",
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

// AddUserToOrganization adds an unmanaged user to an Organization
func (c *Client) AddUserToOrganization(ctx context.Context, opts AddUserToOrganizationOpts) (User, error) {
	endpoint := fmt.Sprintf(
		"%s/users/%s/organizations",
		c.Endpoint,
		opts.User,
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

// RemoveUserFromOrganization removes an unmanaged User from the given Organization.
func (c *Client) RemoveUserFromOrganization(ctx context.Context, opts RemoveUserFromOrganizationOpts) (User, error) {
	endpoint := fmt.Sprintf(
		"%s/users/%s/organizations/%s",
		c.Endpoint,
		opts.User,
		opts.Organization,
	)

	req, err := http.NewRequest(
		http.MethodDelete,
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

func (c *Client) AuthenticateUserWithPassword(ctx context.Context, opts AuthenticateUserWithPasswordOpts) (AuthenticationResponse, error) {
	payload := struct {
		AuthenticateUserWithPasswordOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateUserWithPasswordOpts: opts,
		ClientSecret:                     c.APIKey,
		GrantType:                        "password",
	}

	jsonData, err := json.Marshal(payload)
	fmt.Println(string(jsonData))
	if err != nil {
		return AuthenticationResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/users/sessions/token",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticationResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticationResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticationResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticationResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// AuthenticateUserWithToken authenticates an OAuth user or a managed SSO user that is logging in through SSO, and
// optionally creates a session.
func (c *Client) AuthenticateUserWithToken(ctx context.Context, opts AuthenticateUserWithTokenOpts) (AuthenticationResponse, error) {
	payload := struct {
		AuthenticateUserWithTokenOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateUserWithTokenOpts: opts,
		ClientSecret:                  c.APIKey,
		GrantType:                     "authorization_code",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticationResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/users/sessions/token",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticationResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticationResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticationResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticationResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// AuthenticateUserWithMagicAuth authenticates a user by verifying a one-time code sent to the user's email address by
// the Magic Auth Send Code endpoint.
func (c *Client) AuthenticateUserWithMagicAuth(ctx context.Context, opts AuthenticateUserWithMagicAuthOpts) (AuthenticationResponse, error) {
	payload := struct {
		AuthenticateUserWithMagicAuthOpts
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
	}{
		AuthenticateUserWithMagicAuthOpts: opts,
		ClientSecret:                      c.APIKey,
		GrantType:                         "urn:workos:oauth:grant-type:magic-auth:code",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return AuthenticationResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/users/sessions/token",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		return AuthenticationResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return AuthenticationResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return AuthenticationResponse{}, err
	}

	// Parse the JSON response
	var body AuthenticationResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// CreateEmailVerificationChallenge creates an email verification challenge and emails verification token to user.
func (c *Client) CreateEmailVerificationChallenge(ctx context.Context, opts CreateEmailVerificationChallengeOpts) (ChallengeResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/users/%s/email_verification_challenge",
		c.Endpoint,
		opts.User,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return ChallengeResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return ChallengeResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ChallengeResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ChallengeResponse{}, err
	}

	var body ChallengeResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// CompleteEmailVerification verifies user email using verification token that was sent to the user.
func (c *Client) CompleteEmailVerification(ctx context.Context, opts CompleteEmailVerificationOpts) (User, error) {
	endpoint := fmt.Sprintf(
		"%s/users/email_verification",
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

// CreatePasswordResetChallenge creates a password reset challenge and emails a password reset link to an
// unmanaged user.
func (c *Client) CreatePasswordResetChallenge(ctx context.Context, opts CreatePasswordResetChallengeOpts) (ChallengeResponse, error) {
	endpoint := fmt.Sprintf(
		"%s/users/password_reset_challenge",
		c.Endpoint,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return ChallengeResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return ChallengeResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ChallengeResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ChallengeResponse{}, err
	}

	var body ChallengeResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// CompletePasswordReset resets user password using token that was sent to the user.
func (c *Client) CompletePasswordReset(ctx context.Context, opts CompletePasswordResetOpts) (User, error) {
	endpoint := fmt.Sprintf(
		"%s/users/password_reset",
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

// SendMagicAuthCode creates a one-time Magic Auth code and emails it to the user.
func (c *Client) SendMagicAuthCode(ctx context.Context, opts SendMagicAuthCodeOpts) (MagicAuthChallengeID, error) {
	endpoint := fmt.Sprintf(
		"%s/users/magic_auth/send",
		c.Endpoint,
	)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		bytes.NewBuffer(data),
	)
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return "", err
	}

	var body MagicAuthChallenge
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body.MagicAuthChallengeID, err
}

// VerifySession verifies the session token returned by the authentication request. If the token is authentic and has
// not expired the response will contain the authenticated user and session objects.
func (c *Client) VerifySession(ctx context.Context, opts VerifySessionOpts) (VerifySessionResponse, error) {
	data, err := json.Marshal(opts)
	if err != nil {
		return VerifySessionResponse{}, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/users/sessions/verify",
		bytes.NewReader(data),
	)

	if err != nil {
		return VerifySessionResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return VerifySessionResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return VerifySessionResponse{}, err
	}

	// Parse the JSON response
	var body VerifySessionResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)

	return body, err
}

// RevokeSession revokes a single session, invalidating the token for further verification requests. Either the
// session ID or token must be given to identify the session to revoke.
func (c *Client) RevokeSession(ctx context.Context, opts RevokeSessionOpts) (bool, error) {
	data, err := c.JSONEncode(opts)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/users/sessions/revocations",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return false, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return false, err
	}

	var result bool
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return false, err
	}

	return result, err
}

// RevokeAllSessionsForUser revokes all active sessions for the given user.
func (c *Client) RevokeAllSessionsForUser(ctx context.Context, opts RevokeAllSessionsForUserOpts) (bool, error) {
	// Construct the URL
	url := c.Endpoint + "/users/" + opts.User + "/sessions"

	// Create a new DELETE request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return false, err
	}

	// Add headers to the request
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return false, err
	}

	// Decode the response
	var result bool
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return false, err
	}

	return result, nil
}
