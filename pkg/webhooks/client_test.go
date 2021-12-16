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
	secret := "secret"

	client := webhooks.NewClient(secret)

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
	secret := "secret"

	client := webhooks.NewClient(secret)

	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(time.Now(), "other_secret", body)

	_, err := client.ValidatePayload(header, body)
	if err != webhooks.ErrNoValidSignature {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrNoValidSignature, err)
	}
}

func TestWebhookWithEmptySecret(t *testing.T) {
	secret := "secret"

	client := webhooks.NewClient(secret)

	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(time.Now(), "", body)

	_, err := client.ValidatePayload(header, body)
	if err != webhooks.ErrNoValidSignature {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrNoValidSignature, err)
	}
}

func TestWebhookWithInvalidHeader(t *testing.T) {
	secret := "secret"

	client := webhooks.NewClient(secret)
	body := "{'data': 'foobar'}"

	_, err := client.ValidatePayload("some_junk", body)
	if err != webhooks.ErrInvalidHeader {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrInvalidHeader, err)
	}
}

func TestWebhookWithTimestampOlderThanTolerance(t *testing.T) {
	tolerance := 180 * time.Second
	secret := "secret"
	now := time.Unix(0, 0)

	client := webhooks.NewClient(secret)
	client.SetNow(func() time.Time { return now.Add(tolerance + time.Second) })

	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(now, secret, body)

	_, err := client.ValidatePayload(header, body)
	if err != webhooks.ErrInvalidTimestamp {
		t.Errorf("expected a '%s' error, but got a '%s'", webhooks.ErrInvalidTimestamp, err)
	}
}

func TestWebhookWithCustomTolerance(t *testing.T) {
	tolerance := 240 * time.Second
	secret := "secret"
	now := time.Unix(0, 0)

	client := webhooks.NewClient(secret)
	client.SetNow(func() time.Time { return now.Add(200 * time.Second) })
	client.SetTolerance(tolerance)

	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(now, secret, body)

	actual, err := client.ValidatePayload(header, body)
	if err != nil {
		t.Errorf("expected no error, but got '%s'", err)
	}

	if actual != body {
		t.Errorf("expected output to be '%s', but got '%s'", body, actual)
	}
}

func TestWebhookWithInvalidSignature(t *testing.T) {
	secret := "secret"

	client := webhooks.NewClient(secret)

	body := "{'data': 'foobar'}"
	header := mockWebhookHeader(time.Now(), secret, body)

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
