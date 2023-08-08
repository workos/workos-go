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
	"strings"
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

	// List of the user's organization memberships. Unmanaged users can have zero or multiple memberships.
	// Managed users have exactly one membership.
	OrganizationMemberships []OrganizationMembership `json:"organization_memberships"`

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
	Type UserType `json:"type,omitempty"`

	// Filter Users by their email.
	Email string `json:"email,omitempty"`

	// Filter Users by the organization they are members of.
	Organization string `json:"organization,omitempty"`

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
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`

	// EmailVerified states whether the user's email address was
	// previously verified. You should normally use the Email Verification API
	// to verify a user's email address
	EmailVerified bool `json:"email_verified,omitempty"`
}

type AddUserToOrganizationOpts struct {
	User         string `json:"id"`
	Organization string `json:"organization_id"`
}

type Session struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type AuthenticateUserWithPasswordOpts struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	IPAddress    string `json:"ip_address,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	StartSession bool   `json:"start_session,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}
type AuthenticationResponse struct {
	Session Session `json:"session"`
	User    User    `json:"user"`
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

func (c *Client) AuthenticateUserWithPassword(ctx context.Context, opts AuthenticateUserWithPasswordOpts) (AuthenticationResponse, error) {
	encodedForm, err := query.Values(opts)
	if err != nil {
		return AuthenticationResponse{}, err
	}
	req, err := http.NewRequest(
		http.MethodPost,
		c.Endpoint+"/users/sessions/token",
		strings.NewReader(encodedForm.Encode()),
	)
	if err != nil {
		return AuthenticationResponse{}, err
	}

	// Add headers and context to the request
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
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

// CreateUser create a new user with email password authentication.
// Only unmanaged users can be created directly using the User Management API.
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
