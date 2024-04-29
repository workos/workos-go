package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/workos/workos-go/v4/pkg/workos_errors"

	"github.com/workos/workos-go/v4/internal/workos"
)

// This represents the list of errors that could be raised when using the mfa package
var (
	ErrInvalidType        = errors.New("type must be present and 'sms' or 'totp'")
	ErrIncompleteArgs     = errors.New("need to specify both totp_issuer and totp_user when type is totp")
	ErrNoPhoneNumber      = errors.New("need to specify phone_number when type is sms")
	ErrMissingAuthId      = errors.New("authentication_factor_id' is a required parameter")
	ErrMissingChallengeId = errors.New("challenge_factor_id' is a required parameter")
)

// Client represents a client that performs MFA requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

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

// Type represents the type of Authentication Factor
type FactorType string

// Constants that enumerate the available Types.
const (
	SMS  FactorType = "sms"
	TOTP FactorType = "totp"
)

// EnrollFactorOpts contains the options to create an Authentication Factor.
type EnrollFactorOpts struct {

	// Type of factor to be enrolled (sms or totp).
	Type FactorType

	// Name of the Organization.
	TOTPIssuer string

	// Email of user.
	TOTPUser string

	// Phone Number of the User.
	PhoneNumber string
}

type Factor struct {
	// The authentication factor's unique ID
	ID string `json:"id"`

	// The name of the response type
	Object string `json:"object"`

	// The timestamp of when the request was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the request was updated.
	UpdatedAt string `json:"updated_at"`

	// The type of request either 'sms' or 'totp'
	Type FactorType `json:"type"`

	// Details of the totp response will be 'null' if using sms
	TOTP TOTPDetails `json:"totp"`

	// Details of the sms response will be 'null' if using totp
	SMS SMSDetails `json:"sms"`
}

type TOTPDetails struct {
	QRCode string `json:"qr_code"`
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type SMSDetails struct {
	PhoneNumber string `json:"phone_number"`
}

type ChallengeFactorOpts struct {
	// ID of the authorization factor.
	FactorID string

	// Parameter to customize the message for sms type factors. Must include "{{code}}" if used (opt).
	SMSTemplate string
}

type Challenge struct {
	// The authentication challenge's unique ID
	ID string `json:"id"`

	// The name of the response type.
	Object string `json:"object"`

	// The timestamp of when the request was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the request was updated.
	UpdatedAt string `json:"updated_at"`

	// The timestamp of when the request expires.
	ExpiresAt string `json:"expires_at"`

	// The authentication factor Id used to create the request.
	FactorID string `json:"authentication_factor_id"`
}

type VerifyChallengeOpts struct {
	// The ID of the authentication challenge that provided the user the verification code.
	ChallengeID string

	// The verification code sent to and provided by the end user.
	Code string
}

type VerifyChallengeResponse struct {
	// Return details of the request
	Challenge Challenge `json:"challenge"`

	// Boolean returning if request is valid
	Valid bool `json:"valid"`
}

type VerifyChallengeResponseError struct {
	// Returns string of error code on response with valid: false
	Code string `json:"code"`

	// Returns string of message on response with valid: false
	Message string `json:"message"`
}

type RawVerifyChallengeResponse struct {
	VerifyChallengeResponse
	VerifyChallengeResponseError
}

type DeleteFactorOpts struct {
	// ID of factor to be deleted
	FactorID string
}

type GetFactorOpts struct {
	// ID of the factor.
	FactorID string
}

// Create an Authentication Factor.
func (c *Client) EnrollFactor(
	ctx context.Context,
	opts EnrollFactorOpts,
) (Factor, error) {
	c.once.Do(c.init)

	if opts.Type == "" || (opts.Type != SMS && opts.Type != TOTP) {
		return Factor{}, ErrInvalidType
	}

	if opts.Type == TOTP && (opts.TOTPIssuer == "" || opts.TOTPUser == "") {
		return Factor{}, ErrIncompleteArgs
	}

	if opts.Type == SMS && opts.PhoneNumber == "" {
		return Factor{}, ErrNoPhoneNumber
	}

	postBody, _ := json.Marshal(map[string]string{
		"type":         string(opts.Type),
		"totp_issuer":  opts.TOTPIssuer,
		"totp_user":    opts.TOTPUser,
		"phone_number": opts.PhoneNumber,
	})
	responseBody := bytes.NewBuffer(postBody)

	endpoint := fmt.Sprintf("%s/auth/factors/enroll", c.Endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, responseBody)
	if err != nil {
		return Factor{}, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Factor{}, err
	}
	defer resp.Body.Close()

	if err = workos_errors.TryGetHTTPError(resp); err != nil {
		return Factor{}, err
	}

	var body Factor
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&body)
	return body, err
}

// Initiates the authentication process for the newly created MFA authorization factor, referred to as a challenge.
func (c *Client) ChallengeFactor(
	ctx context.Context,
	opts ChallengeFactorOpts,
) (Challenge, error) {
	c.once.Do(c.init)

	if opts.FactorID == "" {
		return Challenge{}, ErrMissingAuthId
	}

	postBody, _ := json.Marshal(map[string]string{
		"sms_template": opts.SMSTemplate,
	})
	responseBody := bytes.NewBuffer(postBody)

	endpoint := fmt.Sprintf("%s/auth/factors/%s/challenge", c.Endpoint, opts.FactorID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, responseBody)
	if err != nil {
		return Challenge{}, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Challenge{}, err
	}
	defer resp.Body.Close()

	if err = workos_errors.TryGetHTTPError(resp); err != nil {
		return Challenge{}, err
	}

	var body Challenge
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&body)
	return body, err

}

// Deprecated: Use VerifyChallenge instead.
func (c *Client) VerifyFactor(ctx context.Context, opts VerifyChallengeOpts) (interface{}, error) {
	return c.VerifyChallenge(ctx, opts)
}

type VerificationResponseError struct {
	Code    string
	Message string
}

func (r VerificationResponseError) Error() string {
	return fmt.Sprintf("mfa verification failed: %s (code: %s)", r.Message, r.Code)
}

// Verifies the one time password provided by the end-user.
func (c *Client) VerifyChallenge(
	ctx context.Context,
	opts VerifyChallengeOpts,
) (VerifyChallengeResponse, error) {
	c.once.Do(c.init)

	if opts.ChallengeID == "" {
		return VerifyChallengeResponse{}, ErrMissingChallengeId
	}

	postBody, _ := json.Marshal(map[string]string{
		"code": opts.Code,
	})
	responseBody := bytes.NewBuffer(postBody)

	endpoint := fmt.Sprintf("%s/auth/challenges/%s/verify", c.Endpoint, opts.ChallengeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, responseBody)
	if err != nil {
		return VerifyChallengeResponse{}, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return VerifyChallengeResponse{}, err
	}
	defer resp.Body.Close()

	var body RawVerifyChallengeResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&body)
	if err != nil {
		return VerifyChallengeResponse{}, err
	}

	if body.Code != "" {
		return VerifyChallengeResponse{}, VerificationResponseError{body.Code, body.Message}
	}
	return VerifyChallengeResponse{body.Challenge, body.Valid}, nil
}

// Deletes an authentication factor.
func (c *Client) DeleteFactor(
	ctx context.Context,
	opts DeleteFactorOpts,
) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/auth/factors/%s",
		c.Endpoint,
		opts.FactorID,
	)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodDelete,
		endpoint,
		nil,
	)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// Retrieves an authentication factor.
func (c *Client) GetFactor(
	ctx context.Context,
	opts GetFactorOpts,
) (Factor, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/auth/factors/%s", c.Endpoint, opts.FactorID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Factor{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Factor{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Factor{}, err
	}

	var body Factor
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
