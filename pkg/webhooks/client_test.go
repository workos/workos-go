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

	now := time.Now().Round(0).Unix()
	payload := "{'id':'wh_01FHTNQPSYGA4Z25QSZYPY4659','data':{'id':'conn_01EHWNC0FCBHZ3BJ7EGKYXK0E6','name':'Foo Corp's Connection','state':'active','object':'connection','domains':[{'id':'conn_domain_01EHWNFTAFCF3CQAE5A9Q0P1YB','domain':'foo-corp.com','object':'connection_domain'}],'connection_type':'OktaSAML','organization_id':'org_01EHWNCE74X7JSDV0X3SZ3KJNY'},'event':'connection.activated'}"
	stringTime := strconv.FormatInt(now*1000, 10)
	signedPayload := stringTime + "." + payload
	convertedSecret := hmac.New(sha256.New, []byte(secret))
	convertedSecret.Write([]byte(signedPayload))
	expectedSignature := hex.EncodeToString(convertedSecret.Sum(nil))
	header := "t=" + stringTime + ", v1=" + expectedSignature

	actual, err := client.ValidatePayload(header, payload)
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}

	if actual != payload {
		t.Errorf("expected output to be %s, but got %s", payload, actual)
	}
}
