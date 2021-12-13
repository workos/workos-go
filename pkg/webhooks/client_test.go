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

func TestWebhooks(t *testing.T) {
	defaultTolerance := 180 * time.Second
	secret := "secret"

	client := webhooks.NewClient(secret, defaultTolerance)

	now := time.Now()
	body := "{'id':'wh_01FHTNQPSYGA4Z25QSZYPY4659','data':{'id':'conn_01EHWNC0FCBHZ3BJ7EGKYXK0E6','name':'Foo Corp's Connection','state':'active','object':'connection','domains':[{'id':'conn_domain_01EHWNFTAFCF3CQAE5A9Q0P1YB','domain':'foo-corp.com','object':'connection_domain'}],'connection_type':'OktaSAML','organization_id':'org_01EHWNCE74X7JSDV0X3SZ3KJNY'},'event':'connection.activated'}"
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
