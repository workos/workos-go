package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// This represents the list of errors that could be raised when using the webhook package.
var (
	ErrInvalidHeader    = errors.New("webhook has invalid WorkOS header")
	ErrNoValidSignature = errors.New("webhook had no valid signature")
	ErrNotSigned        = errors.New("webhook has no WorkOS header")
	ErrInvalidTimestamp = errors.New("webhook has an invalid timestamp")
	ErrOutsideTolerance = errors.New("webhook has a timestamp that is out of tolerance")
)

// The Client used to interact with Webhooks.
type Client struct {
	now       func() time.Time
	tolerance time.Duration
	secret    string
}

// Constructs a new Client.
func NewClient(secret string) *Client {
	return &Client{now: time.Now, tolerance: 180 * time.Second, secret: secret}
}

// Sets the function used to determine the current time. Usually you'll only
// need to call this for testing purposes.
func (c *Client) SetNow(now func() time.Time) {
	c.now = now
}

// Sets the maximum time tolerance between now and when the webhook timestamp
// was issued.
func (c *Client) SetTolerance(tolerance time.Duration) {
	c.tolerance = tolerance
}

type signedHeader struct {
	timestamp string
	signature string
}

func parseSignatureHeader(header string) (*signedHeader, error) {
	signedHeader := &signedHeader{}
	if header == "" {
		return signedHeader, ErrNotSigned
	}

	// Parse Workos-Signature
	signatureParts := strings.Split(header, ",")
	if len(signatureParts) != 2 {
		return signedHeader, ErrInvalidHeader
	}

	// Turn the timestamp into Unix time
	rawTimestamp := signatureParts[0][2:len(signatureParts[0])]
	signedHeader.timestamp = rawTimestamp

	// Create the signature and check that it exists
	signedHeader.signature = signatureParts[1][4:len(signatureParts[1])]
	if len(signedHeader.signature) == 0 {
		return signedHeader, ErrNoValidSignature
	}

	return signedHeader, nil
}

func (c *Client) checkTimestamp(timestamp string) error {
	intTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidHeader
	}

	formattedTime := time.Unix(intTimestamp/1000, 0)
	currentTime := c.now().Round(0)

	diff := currentTime.Sub(formattedTime)

	if diff < c.tolerance {
		return nil
	} else {
		return ErrInvalidTimestamp
	}
}

func (c *Client) checkSignature(bodyString string, rawTimestamp string, signature string) error {
	unhashedDigest := rawTimestamp + "." + bodyString
	hash := hmac.New(sha256.New, []byte(c.secret))

	hash.Write([]byte(unhashedDigest))

	digest := hex.EncodeToString(hash.Sum(nil))

	if signature == digest {
		return nil
	} else {
		return ErrNoValidSignature
	}
}

func (c *Client) ValidatePayload(workosHeader string, bodyString string) (string, error) {
	header, err := parseSignatureHeader(workosHeader)
	if err != nil {
		return "", err
	}

	if err := c.checkTimestamp(header.timestamp); err != nil {
		return "", err
	}

	if err := c.checkSignature(bodyString, header.timestamp, header.signature); err != nil {
		return "", err
	}

	return bodyString, nil
}
