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

// Define signedHeader
type signedHeader struct {
	timestamp string
	signature string
}

// This represents the list of errors that could be raised when using the webhook package.
var (
	ErrInvalidHeader    = errors.New("webhook has invalid WorkOS header")
	ErrNoValidSignature = errors.New("webhook had no valid signature")
	ErrNotSigned        = errors.New("webhook has no WorkOS header")
	ErrInvalidTimestamp = errors.New("webhook has an invalid timestamp")
	ErrOutsideTolerance = errors.New("webhook has a timestamp that is out of tolerance")
)

func parseSignatureHeader(header string) (*signedHeader, error) {
	sh := &signedHeader{}
	if header == "" {
		return sh, ErrNotSigned
	}

	// Parse Workos-Signature
	s := strings.Split(header, ",")
	if len(s) != 2 {
		return sh, ErrInvalidHeader
	}

	// Turn the timestamp into Unix time
	rawTimestamp := s[0][2:len(s[0])]
	sh.timestamp = rawTimestamp

	// Create the signature and check that it exists
	sh.signature = (s[1][4:len(s[1])])
	if len(sh.signature) == 0 {
		return sh, ErrNoValidSignature
	}

	return sh, nil
}

func checkTimestamp(timestamp string, defaultTolerance time.Duration) error {
	intTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidHeader
	}
	// Transform Timestamp into unix time in seconds
	formattedTime := time.Unix(intTimestamp/1000, 0)
	// Get current time
	currentTime := time.Now().Round(0)
	// Calculate the difference between current time and the formatted time
	diff := currentTime.Sub(formattedTime)
	// Compare the difference in the time to the default tolerance
	if diff < defaultTolerance {
		return nil
	} else {
		return ErrInvalidTimestamp
	}
}

func checkSignature(bodyString string, rawTimestamp string, signature string, secret string) error {
	// Create the digest
	unhashedDigest := (rawTimestamp + "." + bodyString)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(unhashedDigest))

	// Get result and encode as hexadecimal string
	digest := hex.EncodeToString(h.Sum(nil))

	// Return an error if the signature and digest aren't equal
	if signature == digest {
		return nil
	} else {
		return ErrNoValidSignature
	}
}

func validatePayload(workosHeader string, bodyString string, secret string, defaultTolerance time.Duration) (string, error) {
	header, err := parseSignatureHeader(workosHeader)
	if err != nil {
		return "", err
	}

	if err := checkTimestamp(header.timestamp, defaultTolerance); err != nil {
		return "", err
	}

	if err := checkSignature(bodyString, header.timestamp, header.signature, secret); err != nil {
		return "", err
	}

	return bodyString, nil
}
