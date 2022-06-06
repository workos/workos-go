package audittrail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/pkg/workos_errors"

	"github.com/google/go-querystring/query"

	"github.com/workos/workos-go/internal/workos"
	"github.com/workos/workos-go/pkg/common"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Order represents the order of records.
type Order string

// Constants that enumerate the available orders.
const (
	Asc  Order = "asc"
	Desc Order = "desc"
)

// Client represents a client that performs audittrail requests to WorkOS API.
type Client struct {
	// The WorkOS api key. It can be found in
	// https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to post audit trail events to WorkOS. Defaults
	// to http.Client.
	HTTPClient *http.Client

	// The endpoint used to request Workos. Defaults to
	// https://api.workos.com/events.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

// EventOpts represents arguments to create an Audit Trail event.
type EventOpts struct {
	// Specific activity performed by the actor.
	Action string `json:"action"`

	// Corresponding CRUD category of the Event.
	ActionType string `json:"action_type"`

	// Display name of the entity performing the action.
	ActorName string `json:"actor_name"`

	// Unique identifier of the entity performing the action.
	ActorID string `json:"actor_id"`

	// A single domain containing related members.
	Group string `json:"group"`

	// A key that ensures that the same event is not processed multiple times.
	// Once the event is sent for the first time, the lock on the key expires
	// after 24 hours.

	// If no key is provided or the key is empty, the key will not be attached
	// to the request.
	IdempotencyKey string `json:"-"`

	// An ip address that locates where the audit trail occurred.
	Location string `json:"location"`

	// The event metadata. It can't contain more than 50 keys. A key can't
	// exeed 40 characters.
	Metadata Metadata `json:"metadata,omitempty"`

	// The time when the audit trail occurred.
	//
	// Defaults to time.Now().
	OccurredAt time.Time `json:"occurred_at"`

	// Display name of the object or resource that is being acted upon.
	TargetName string `json:"target_name"`

	// Unique identifier of the object or resource being acted upon.
	TargetID string `json:"target_id"`
}

// Metadata represents metadata to be attached to an audit trail event.
type Metadata map[string]interface{}

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
func (c *Client) Publish(ctx context.Context, e EventOpts) error {
	c.once.Do(c.init)

	if err := e.Metadata.validate(); err != nil {
		return err
	}

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
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if e.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", e.IdempotencyKey)
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// ListEventsOpts contains options to fetch Audit Trail events.
type ListEventsOpts struct {
	// List of Groups to filter for.
	Group []string `url:"group,brackets,omitempty"`

	// List of Actions to filter for.
	Action []string `url:"action,brackets,omitempty"`

	// List of Action Types to filter for.
	ActionType []string `url:"action_type,brackets,omitempty"`

	// List of Actor Names to filter for.
	ActorName []string `url:"actor_name,brackets,omitempty"`

	// List of Actor IDs to filter for.
	ActorID []string `url:"actor_id,brackets,omitempty"`

	// List of Target Names to filter for.
	TargetName []string `url:"target_name,brackets,omitempty"`

	// List of Target IDs to filter for.
	TargetID []string `url:"target_id,brackets,omitempty"`

	// ISO-8601 datetime of when an event occurred.
	OccurredAt string `url:"occurred_at,omitempty"`

	// ISO-8601 datetime of when an event occurred after.
	OccurredAtGt string `url:"occurred_at_gt,omitempty"`

	// ISO-8601 datetime of when an event occurred at or after.
	OccurredAtGte string `url:"occurred_at_gte,omitempty"`

	// ISO-8601 datetime of when an event occurred before.
	OccurredAtLt string `url:"occurred_at_lt,omitempty"`

	// ISO-8601 datetime of when an event occured at or before.
	OccurredAtLte string `url:"occurred_at_lte,omitempty"`

	// Keyword search.
	Search string `url:"search,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Event ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Event ID.
	After string `url:"after,omitempty"`
}

// EventAction describes an Audit Trail Event Action record.
type EventAction struct {
	// Event Action identifier.
	ID string `json:"id"`

	// Event Action name.
	Name string `json:"name"`
}

// Event describes an Audit Trail Event record.
type Event struct {
	// Event identifier.
	ID string `json:"id"`

	// A single domain containing related members.
	Group string `json:"group"`

	// Identifier for where the Event originated.
	Location string `json:"location"`

	// Latitude for where the Event originated.
	Latitude string `json:"latitude"`

	// Longitude for where the Event originated.
	Longitude string `json:"longitude"`

	// Corresponding CRUD category of the Event.
	Type string `json:"event_type"`

	// Display name of the entity performing the action.
	ActorName string `json:"actor_name"`

	// Unique identifier of the entity performing the action.
	ActorID string `json:"actor_id"`

	// Display name of the object or resource that is being acted upon.
	TargetName string `json:"target_name"`

	// Unique identifier of the object or resource being acted upon.
	TargetID string `json:"target_id"`

	// ISO-8601 datetime at which the Event happened.
	OccurredAt string `json:"occurred_at"`

	// Specific activity performed by the actor.
	Action EventAction `json:"action"`

	// Arbitrary key-value data containing information associated with the Event
	Metadata Metadata `json:"metadata"`
}

// ListEventsResponse describes the response structure when requesting
// Audit Trail events.
type ListEventsResponse struct {
	// List of Events.
	Data []Event `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// ListEvents gets a list of Audit Trail events.
func (c *Client) ListEvents(ctx context.Context, opts ListEventsOpts) (ListEventsResponse, error) {
	c.once.Do(c.init)

	req, err := http.NewRequest(
		http.MethodGet,
		c.Endpoint,
		nil,
	)
	if err != nil {
		return ListEventsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	v, err := query.Values(opts)
	if err != nil {
		return ListEventsResponse{}, err
	}

	req.URL.RawQuery = v.Encode()
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListEventsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListEventsResponse{}, err
	}

	var body ListEventsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// Merges the given metadata. Values from m are not overridden by the ones from
// other.
func (m Metadata) merge(other Metadata) {
	for k, v := range other {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
}

func (m Metadata) validate() error {
	if len(m) > 50 {
		return errTooMuchMetadataKeys
	}

	for k := range m {
		if l := len(k); l > 40 {
			return fmt.Errorf("metadata key %q exceed 40 characters: %d", k, l)
		}
	}

	return nil
}

func defaultTime(t time.Time) time.Time {
	if t == (time.Time{}) {
		t = time.Now().UTC()
	}
	return t
}
