package webhooks_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/workos-inc/workos-go/pkg/webhooks"
	"strconv"
	"testing"
	"time"
)

func TestWebhookWithValidHeader(t *testing.T) {
	defaultTolerance := 180 * time.Second
	secret := "secret"

	client := webhooks.NewClient(secret, defaultTolerance)

	now := time.Now()
	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(now, secret, body)

	actual, err := client.ValidatePayload(header, body)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}

	if actual != body {
		t.Errorf("expected output to be '%s', but got '%s'", body, actual)
	}
}

func TestWebhookWithInvalidSecret(t *testing.T) {
	defaultTolerance := 180 * time.Second
	secret := "secret"

	client := webhooks.NewClient(secret, defaultTolerance)

	now := time.Now()
	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(now, "other_secret", body)

	_, err := client.ValidatePayload(header, body)
	if err != webhooks.ErrNoValidSignature {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrNoValidSignature, err)
	}
}

func TestWebhookWithEmptySecret(t *testing.T) {
	defaultTolerance := 180 * time.Second
	secret := "secret"

	client := webhooks.NewClient(secret, defaultTolerance)

	now := time.Now()
	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(now, "", body)

	_, err := client.ValidatePayload(header, body)
	if err != webhooks.ErrNoValidSignature {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrNoValidSignature, err)
	}
}

func TestWebhookWithInvalidHeader(t *testing.T) {
	defaultTolerance := 180 * time.Second
	secret := "secret"

	client := webhooks.NewClient(secret, defaultTolerance)
	body := "{'data': 'foobar'}"

	_, err := client.ValidatePayload("some_junk", body)
	if err != webhooks.ErrInvalidHeader {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrInvalidHeader, err)
	}
}

func TestWebhookWithTimestampOlderThanTolerance(t *testing.T) {
	defaultTolerance := 180 * time.Second
	secret := "secret"
	now := time.Unix(0, 0)

	client := webhooks.NewClient(secret, defaultTolerance)
	client.SetNow(func() time.Time { return now })

	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(now.Add(defaultTolerance+time.Second), "", body)

	_, err := client.ValidatePayload(header, body)
	if err != webhooks.ErrInvalidTimestamp {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrInvalidTimestamp, err)
	}
}

func TestWebhookWithInvalidSignature(t *testing.T) {
	defaultTolerance := 180 * time.Second
	secret := "secret"

	client := webhooks.NewClient(secret, defaultTolerance)

	now := time.Now()
	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(now, secret, body)

	_, err := client.ValidatePayload(header, "{'data': 'bazbiz'}")
	if err != webhooks.ErrNoValidSignature {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrNoValidSignature, err)
	}
}

func mockWebhookHeader(now time.Time, secret string, body string) string {
	stringTime := strconv.FormatInt(now.Round(0).Unix()*1000, 10)
	signedBody := stringTime + "." + body
	convertedSecret := hmac.New(sha256.New, []byte(secret))
	convertedSecret.Write([]byte(signedBody))
	expectedSignature := hex.EncodeToString(convertedSecret.Sum(nil))

	return "t=" + stringTime + ", v1=" + expectedSignature
}
