package webhooks

import (
	"errors"
	"time"
)

// Sets default Tolerance to 3 minutes
const DefaultTolerance time.Duration = 180 * time.Second

// This represents the list of errors that could be raised when using the webhook package.
var (
	ErrInvalidHeader    = errors.New("webhook has invalid WorkOS header")
	ErrNoValidSignature = errors.New("webhook had no valid signature")
	ErrNotSigned        = errors.New("webhook has no WorkOS header")
	ErrInvalidTimestamp = errors.New("webhook has an invalid timestamp")
	ErrOutsideTolerance = errors.New("webhook has a timestamp that is out of tolerance")
)

testSignature = "t=1633109865253, v1=5d5d02e5baab3bc1376c0ee603534104605f8a4fbaa3afeed60bde9a9bd7cebc"

testData = {
    "id": "wh_01FGYEXWQJXJXWQZ5WW2QRFNK7",
    "data": {
        "id": "conn_01EHWNC0FCBHZ3BJ7EGKYXK0E6",
        "name": "Foo Corp's Connection",
        "state": "active",
        "object": "connection",
        "domains": [
            {
                "id": "conn_domain_01EHWNFTAFCF3CQAE5A9Q0P1YB",
                "domain": "foo-corp.com",
                "object": "connection_domain"
            }
        ],
        "connection_type": "OktaSAML",
        "organization_id": "org_01EHWNCE74X7JSDV0X3SZ3KJNY"
    },
    "event": "connection.activated"
}

func parseSignatureHeader(header string) (signedHeader, error) {
	sh := {}

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
	sh.timesstamp = time.Unix(intTimestamp/1000, 0)

	// Create the signature and check that it exists
	sh.signature := (s[1][4:len(s[1])])
	if len(sh.signature)) == 0 {
		return sh, ErrNoValidSignature
	}

	return sh, nil
}

func verifyHeader () {
	header, err := parseSignatureHeader(sigHeader)
}