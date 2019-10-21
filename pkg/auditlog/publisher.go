package alog

import (
	"bytes"
	"encoding/json"
	"errors"
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

	// The amount of time an event is retried when an error occurs while being
	// published. Defaults to 0.
	Retries int

	// The size of the internal queue. Defaults to 1.
	QueueSize int

	queue     chan job
	stop      chan struct{}
	once      sync.Once
	waitGroup sync.WaitGroup
}

// Publish enqueues the given events to be published to WorkOS.
func (p *Publisher) Publish(events ...Event) {
	p.once.Do(p.init)

	for _, e := range events {
		p.queue <- job{
			event:           e,
			indempotencyKey: uuid.New().String(),
		}
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
		p.QueueSize = 1
	}

	p.queue = make(chan job, p.QueueSize)
	p.stop = make(chan struct{})

	go p.loop()
}

func (p *Publisher) loop() {
	for j := range p.queue {
		// This is to capture j value in order to not have the same value passed
		// in difference goroutines.
		job := j

		p.waitGroup.Add(1)

		// The time to post events 1 by 1 bring the risk of blocking enqueueing
		// new events, which could disrupt the flow of the customer that uses
		// this package.
		//
		// Until we have an api call that allows to send events by batch,
		// We are creating a goroutine that process the publish job in order
		// to avoid blocking the caller in case of the queue channel is full.
		go func() {
			defer p.waitGroup.Done()

			if err := p.publish(job); err != nil {
				p.Log("publishing %+v failed: %s", job.event, err)

				job.retries++
				if job.retries > p.Retries {
					p.Log("reenqueuing event: %+v: retry %v", job.event, job.retries)
					p.queue <- job
				}
			}
		}()
	}

	p.waitGroup.Wait()
	p.stop <- struct{}{}
}

func (p *Publisher) publish(j job) error {
	data, err := p.JSONEncode(j.event)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, p.Endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", j.indempotencyKey)
	req.Header.Set("Authorization", "Bearer "+p.APIKey)

	res, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return errors.New(string(body))
	}

	return nil
}

// Close stops publishings audit log events and releases allocated resources.
// It waits for pending events to be sent before returning.
func (p *Publisher) Close() {
	if p.queue != nil {
		close(p.queue)
		<-p.stop
		close(p.stop)
	}
}

type job struct {
	event           Event
	indempotencyKey string
	retries         int
}
