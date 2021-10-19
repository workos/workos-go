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
	signedHeader.signature = (signatureParts[1][4:len(signatureParts[1])])
	if len(signedHeader.signature) == 0 {
		return signedHeader, ErrNoValidSignature
	}

	return signedHeader, nil
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
	hash := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	hash.Write([]byte(unhashedDigest))

	// Get result and encode as hexadecimal string
	digest := hex.EncodeToString(hash.Sum(nil))

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
