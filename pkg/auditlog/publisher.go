package alog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
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

	// The function used to log errors. Defaults to log.Printf.
	Log func(format string, v ...interface{})

	// The size of the internal queue. Defaults to 512.
	QueueSize int

	queue  chan Event
	cancel func()
	stop   chan struct{}
	once   sync.Once
}

// Publish enqueues the given events to be published to WorkOS.
func (p *Publisher) Publish(events ...Event) {
	p.once.Do(p.init)

	for _, e := range events {
		e.Location = defaultLocation(e.Location)
		e.OccurredAt = defaultTime(e.OccurredAt)
		p.queue <- e
	}
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

	if p.Log == nil {
		p.Log = log.Printf
	}

	if p.QueueSize < 1 {
		p.QueueSize = 512
	}

	p.queue = make(chan Event, p.QueueSize)
	p.stop = make(chan struct{})

	ctx := context.Background()
	ctx, p.cancel = context.WithCancel(ctx)

	go p.loop(ctx)
}

func (p *Publisher) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			p.stop <- struct{}{}
			return

		case e := <-p.queue:
			// This is to capture e value in order to not have the same value
			// passed in different goroutines.
			event := e
			event.indempotencyKey = uuid.New().String()

			// The time to post events 1 by 1 bring the risk of blocking
			// enqueueing new events, which could disrupt the flow of the
			// customer that uses this package.
			//
			// Until we have an api call that allows to send events by batch,
			// We are creating a goroutine that process the publish job in order
			// to avoid blocking the caller in case of the queue channel is
			// full.
			go func() {
				if err := p.publish(ctx, event); err != nil {
					p.Log("publishing %+v failed: %s", event, err)
				}
			}()
		}
	}
}

func (p *Publisher) publish(ctx context.Context, e Event) error {
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
	req.Header.Set("Idempotency-Key", e.indempotencyKey)
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

// Close stops publishings audit log events and releases allocated resources.
// It waits for pending events to be sent before returning.
func (p *Publisher) Close() {
	if p.queue != nil {
		p.cancel()
		<-p.stop
		close(p.stop)
		close(p.queue)
	}
}
