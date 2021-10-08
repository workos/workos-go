package webhooks

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sets default Tolerance to 3 minutes
const DefaultTolerance time.Duration = 180 * time.Second

// Define signedHeader
type signedHeader struct {
	timestamp int64
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

const testSignature string = "t=1633109865253, v1=5d5d02e5baab3bc1376c0ee603534104605f8a4fbaa3afeed60bde9a9bd7cebc"

func parseSignatureHeader(header string) (*signedHeader, error) {
	sh := &signedHeader{}

	if header == "" {
		return sh, ErrNotSigned
	}

	//Parse Workos-Signature
	s := strings.Split(header, ",")

	if len(s) != 2 {
		return sh, ErrInvalidHeader
	}

	// Turn the timestamp into Unix time
	rawTimestamp := s[0][2:len(s[0])]
	timestamp, err := strconv.ParseInt(rawTimestamp, 10, 64)
	if err != nil {
		return sh, ErrInvalidHeader
	}
	sh.timestamp = timestamp

	// Create the signature and check that it exists
	sh.signature = (s[1][4:len(s[1])])
	if len(sh.signature) == 0 {
		return sh, ErrNoValidSignature
	}

	return sh, nil
}

func checkTimestamp(intTimestamp int64) error {
	formattedTime := time.Unix(intTimestamp/1000, 0)
	//get current time
	currentTime := time.Now().Round(0)
	//calculate the difference between current time and the formatted time
	diff := currentTime.Sub(formattedTime)

	if diff < DefaultTolerance {
		return nil
	} else {
		return ErrInvalidTimestamp
	}
}

func verifyHeader(testSignature string) error {
	header, err := parseSignatureHeader(testSignature)
	if err != nil {
		return err
	}
	fmt.Println(header)

	//check timestamp tolerance
	if err := checkTimestamp(header.timestamp); err != nil {
		return err
	}

	//check signatures

	return ErrNoValidSignature
}
