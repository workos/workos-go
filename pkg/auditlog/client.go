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

// Client represents a client that performs auditlog request to WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to post audit log events to WorkOS. Defaults
	// to http.Client.
	HTTPClient *http.Client

	// The endpoint used to request Workos. Defaults to
	// https://api.workos.com/events.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com/events"
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

// Publish publishes the given event.
func (c *Client) Publish(ctx context.Context, e Event) error {
	c.once.Do(c.init)

	if err := e.Metadata.validate(); err != nil {
		return err
	}

	e.IdempotencyKey = defaultIdempotencyKey(e.IdempotencyKey)
	e.OccurredAt = defaultTime(e.OccurredAt)

	data, err := c.JSONEncode(e)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.Endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", e.IdempotencyKey)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	res, err := c.HTTPClient.Do(req)
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
