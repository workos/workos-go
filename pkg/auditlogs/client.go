package auditlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/workos/workos-go/pkg/workos_errors"

	"github.com/workos/workos-go/internal/workos"
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

// Client represents a client that performs auditlogs requests to WorkOS API.
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

// AuditLogEventOpts represents arguments to create an Audit Logs event.
type AuditLogEventOpts struct {
	// Organization identifier
	Organization string `json:"organization_id"`

	// Event payload
	Event Event `json:"event"`
	// If no key is provided or the key is empty, the key will not be attached
	// to the request.
	IdempotencyKey string `json:"-"`
}

type Event struct {
	// Represents the activity performed by the actor.
	Action string `json:"action"`

	// The schema version of the event
	Version string `json:"version"`

	// The time when the audit trail occurred.
	//
	// Defaults to time.Now().
	OccurredAt time.Time `json:"occurred_at"`

	// Describes the entity that generated the event
	Actor Actor `json:"actor"`

	// List of event target
	Targets []Target `json:"targets"`

	// Attributes of event context
	Context Context `json:"context"`

	// Event metadata.
	Metadata Metadata `json:"metadata"`
}

// Metadata represents metadata to be attached to an audit trail event.
type Metadata map[string]interface{}

type Context struct {
	// Place from where the event is fired
	Location string

	// User Agent identity information of the event actor
	UserAgent string
}

type Target struct {
	Id string

	Name string

	Type string

	Metadata Metadata
}

type Actor struct {
	Id string

	Name string

	Type string

	Metadata Metadata
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com/audit_logs/events"
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

// CreateEvent creates an Audit Log event.
func (c *Client) CreateEvent(ctx context.Context, e AuditLogEventOpts) error {
	c.once.Do(c.init)

	e.Event.OccurredAt = defaultTime(e.Event.OccurredAt)

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

// Merges the given metadata. Values from m are not overridden by the ones from
// other.
func (m Metadata) merge(other Metadata) {
	for k, v := range other {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
}

func defaultTime(t time.Time) time.Time {
	if t == (time.Time{}) {
		t = time.Now().UTC()
	}
	return t
}
