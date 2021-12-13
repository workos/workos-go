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
		t.Errorf("expected output to be %s, but got %s", body, actual)
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
