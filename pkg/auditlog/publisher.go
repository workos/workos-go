package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

// Publisher represents an audit log events publisher that posts events to
// WorkOS asynchronously.
type Publisher struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to post audit log events to WorkOS. Defaults
	// to http.Client.
	Client *http.Client

	// The endpoint used to request Workos. Defaults to
	// https://api.workos.com/events.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (p *Publisher) init() {
	if p.Client == nil {
		p.Client = &http.Client{Timeout: 10 * time.Second}
	}

	if p.Endpoint == "" {
		p.Endpoint = "https://api.workos.com/events"
	}

	if p.JSONEncode == nil {
		p.JSONEncode = json.Marshal
	}
}

// Publish publishes the given event.
func (p *Publisher) Publish(ctx context.Context, e Event) error {
	p.once.Do(p.init)

	e.IdempotencyKey = defaultIdempotencyKey(e.IdempotencyKey)
	e.Location = defaultLocation(e.Location)
	e.OccurredAt = defaultTime(e.OccurredAt)

	data, err := p.JSONEncode(e)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, p.Endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", e.IdempotencyKey)
	req.Header.Set("Authorization", "Bearer "+p.APIKey)

	res, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("%s: %s", res.Status, err)
		}
		return fmt.Errorf("%s: %s", res.Status, body)
	}

	return nil
}
