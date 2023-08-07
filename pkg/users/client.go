package users

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/workos/workos-go/v2/internal/workos"
	"github.com/workos/workos-go/v2/pkg/workos_errors"
	"net/http"
	"strings"
	"sync"
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

// Client represents a client that fetch SSO data from WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	//
	// REQUIRED.
	APIKey string

	// The WorkOS Client ID (eg. client_01JG3BCPTRTSTTWQR4VSHXGWCQ).
	//
	// REQUIRED.
	ClientID string

	// The endpoint to WorkOS API.
	//
	// Defaults to https://api.workos.com.
	Endpoint string

	// The http.Client that is used to send request to WorkOS.
	//
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")

	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: time.Second * 15}
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

// UserType represents the type of the User
type UserType string

// Constants that enumerate the UserType
const (
	Unmanaged UserType = "unmanaged"
	Managed   UserType = "managed"
)

type Organization struct {
	// The Organization's unique identifier.
	ID string `json:"id"`

	// The Organization's name.
	Name string `json:"name"`
}

type OrganizationMembership struct {
	// Contains the ID and name of the associated Organization.
	Organization Organization `json:"organization"`

	// CreatedAt is the timestamp of when the OrganizationMembership was created.
	CreatedAt string `json:"created_at"`

	// UpdatedAt is the timestamp of when the OrganizationMembership was updated.
	UpdatedAt string `json:"updated_at"`
}

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

// GetUser returns details of an existing user
// WorkOS SSO.
func (c *Client) GetUser(ctx context.Context, opts GetUserOpts) (User, error) {
	c.once.Do(c.init)

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
