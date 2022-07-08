package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/workos/workos-go/pkg/workos_errors"

	"github.com/workos/workos-go/internal/workos"
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

// GetEnrollsOpts contains the options to create an Authentication Factor.
type GetEnrollOpts struct {
	// Type of factor to be enrolled (sms or totp).
	Type string

	// Name of the Organization.
	TotpIssuer string

	// Email of user.
	TotpUser string

	// Phone Number of the User.
	PhoneNumber string
}

type EnrollResponse struct {
	// The authentication factor's unique ID
	ID string `json:"id"`

	// The name of the response type
	Object string `json:"object"`

	// The timestamp of when the request was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the request was updated.
	UpdatedAt string `json:"updated_at"`

	// The type of request either 'sms' or 'totp'
	Type string `json:"type"`

	// Details of the totp response will be 'null' if using sms
	Totp map[string]interface{} `json:"totp"`

	// Details of the sms response will be 'null' if using totp
	Sms map[string]interface{} `json:"sms"`
}

type ChallengeOpts struct {
	// ID of the authorization factor.
	AuthenticationFactorID string

	// Parameter to customize the message for sms type factors. Must include "{{code}}" if used (opt).
	SMSTemplate string
}

type ChallengeResponse struct {
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
	AuthenticationFactorID string `json:"authentication_factor_id"`
}

type VerifyOpts struct {
	// The ID of the authentication challenge that provided the user the verification code.
	AuthenticationChallengeID string

	// The verification code sent to and provided by the end user.
	Code string
}

type VerifyResponse struct {
	// Return details of the request
	Challenge map[string]interface{} `json:"challenge"`

	// Boolean returning if request is valid
	Valid bool `json:"valid"`
}

type VerifyResponseError struct {
	// Returns string of error code on response with valid: false
	Code string `json:"code"`

	// Returns string of message on response with valid: false
	Message string `json:"message"`
}

type RawVerifyResponse struct {
	VerifyResponse
	VerifyResponseError
}

// Create an Authentication Factor.
func (c *Client) EnrollFactor(
	ctx context.Context,
	opts GetEnrollOpts,
) (EnrollResponse, error) {
	c.once.Do(c.init)

	if opts.Type == "" || (opts.Type != "sms" && opts.Type != "totp") {
		return EnrollResponse{}, ErrInvalidType
	}

	if opts.Type == "totp" && (opts.TotpIssuer == "" || opts.TotpUser == "") {
		return EnrollResponse{}, ErrIncompleteArgs
	}

	if opts.Type == "sms" && opts.PhoneNumber == "" {
		return EnrollResponse{}, ErrNoPhoneNumber
	}

	postBody, _ := json.Marshal(map[string]string{
		"type":         opts.Type,
		"totp_issuer":  opts.TotpIssuer,
		"totp_user":    opts.TotpUser,
		"phone_number": opts.PhoneNumber,
	})
	responseBody := bytes.NewBuffer(postBody)

	endpoint := fmt.Sprintf("%s/auth/factors/enroll", c.Endpoint)
	req, err := http.NewRequest("POST", endpoint, responseBody)
	if err != nil {
		log.Panic(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return EnrollResponse{}, err
	}

	if err = workos_errors.TryGetHTTPError(resp); err != nil {
		return EnrollResponse{}, err
	}

	var body EnrollResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&body)
	return body, err
}

// Initiates the authentication process for the newly created MFA authorization factor, referred to as a challenge.
func (c *Client) ChallengeFactor(
	ctx context.Context,
	opts ChallengeOpts,
) (ChallengeResponse, error) {
	c.once.Do(c.init)

	if opts.AuthenticationFactorID == "" {
		return ChallengeResponse{}, ErrMissingAuthId
	}

	postBody, _ := json.Marshal(map[string]string{
		"sms_template": opts.SMSTemplate,
	})
	responseBody := bytes.NewBuffer(postBody)

	endpoint := fmt.Sprintf("%s/auth/factors/%s/challenge", c.Endpoint, opts.AuthenticationFactorID)
	req, err := http.NewRequest("POST", endpoint, responseBody)
	if err != nil {
		log.Panic(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ChallengeResponse{}, err
	}

	if err = workos_errors.TryGetHTTPError(resp); err != nil {
		return ChallengeResponse{}, err
	}

	var body ChallengeResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&body)
	return body, err

}

// Deprecated: Use VerifyChallenge instead.
func (c *Client) VerifyFactor(
	ctx context.Context,
	opts VerifyOpts,
) (interface{}, error) {
	return VerifyChallenge(ctx, opts)
}

// Verifies the one time password provided by the end-user.
func (c *Client) VerifyChallenge(
	ctx context.Context,
	opts VerifyOpts,
) (interface{}, error) {
	c.once.Do(c.init)

	if opts.AuthenticationChallengeID == "" {
		return VerifyResponse{}, ErrMissingChallengeId
	}

	postBody, _ := json.Marshal(map[string]string{
		"code": opts.Code,
	})
	responseBody := bytes.NewBuffer(postBody)

	endpoint := fmt.Sprintf("%s/auth/challenges/%s/verify", c.Endpoint, opts.AuthenticationChallengeID)
	req, err := http.NewRequest("POST", endpoint, responseBody)
	if err != nil {
		log.Panic(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return VerifyResponse{}, err
	}

	var body RawVerifyResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&body)

	if body.Code != "" {
		return VerifyResponseError{body.Code, body.Message}, err
	} else {
		return VerifyResponse{body.Challenge, body.Valid}, err
	}

}
