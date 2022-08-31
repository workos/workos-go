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
	// The WorkOS API key. It can be found in
	// https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to post Audit Log events to WorkOS. Defaults
	// to http.Client.
	HTTPClient *http.Client

	// The endpoint used to request WorkOS AuditLog events creation endpoint.
	// Defaults to https://api.workos.com/audit_logs/events.
	EventsEndpoint string

	// The endpoint used to request WorkOS AuditLog events creation endpoint.
	// Defaults to https://api.workos.com/audit_logs/exports.
	ExportsEndpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

// AuditLogEventOpts represents arguments to create an Audit Logs event.
type AuditLogEventOpts struct {
	// Organization identifier
	Organization string `json:"organization_id" binding:"required"`

	// Event payload
	Event Event `json:"event" binding:"required"`

	// If no key is provided or the key is empty, the key will not be attached
	// to the request.
	IdempotencyKey string `json:"-"`
}

type Event struct {
	// Represents the activity performed by the actor.
	Action string `json:"action"`

	// The schema version of the event
	Version int `json:"version,omitempty"`

	// The time when the audit trail occurred.
	// Defaults to time.Now().
	OccurredAt time.Time `json:"occurred_at"`

	// Describes the entity that generated the event
	Actor Actor `json:"actor"`

	// List of event target
	Targets []Target `json:"targets"`

	// Attributes of event context
	Context Context `json:"context"`

	// Event metadata.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Context describes the event location and user agent
type Context struct {
	// Place from where the event is fired
	Location string `json:"location"`

	// User Agent identity information of the event actor
	UserAgent string `json:"user_agent"`
}

// Target describes event entity's
type Target struct {
	Id string `json:"id"`

	Name string `json:"name"`

	Type string `json:"type"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Actor describes the entity that generated the event
type Actor struct {
	Id string `json:"id"`

	Name string `json:"name"`

	Type string `json:"type"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type CreateExportOpts struct {
	// Organization identifier
	Organization string `json:"organization_id"`

	// ISO-8601 start datetime the date range filter
	RangeStart string `json:"range_start"`

	// ISO-8601 start datetime the date range filter
	RangeEnd string `json:"range_end"`

	// Optional list of actions to filter
	Actions []string `json:"actions,omitempty"`

	// Optional list of actors to filter
	Actors []string `json:"actors,omitempty"`

	// Optional list of targets to filter
	Targets []string `json:"targets,omitempty"`
}

type CreateExportResponse struct {
	Object    string `json:"object"`
	Id        string `json:"id"`
	State     string `json:"state"`
	Url       string `json:"url"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type GetExportOpts struct {
	ExportId string `json:"export_id" binding:"required"`
}

type GetExportResponse struct {
	Object    string `json:"object"`
	Id        string `json:"id"`
	State     string `json:"state"`
	Url       string `json:"url"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if c.EventsEndpoint == "" {
		c.EventsEndpoint = "https://api.workos.com/audit_logs/events"
	}

	if c.ExportsEndpoint == "" {
		c.ExportsEndpoint = "https://api.workos.com/audit_logs/exports"
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

	req, err := http.NewRequest(http.MethodPost, c.EventsEndpoint, bytes.NewBuffer(data))
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

// CreateExport creates an export of Audit Log events. You can specify some filters.
func (c *Client) CreateExport(ctx context.Context, e CreateExportOpts) (CreateExportResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(e)
	if err != nil {
		return CreateExportResponse{}, err
	}

	req, err := http.NewRequest(http.MethodPost, c.ExportsEndpoint, bytes.NewBuffer(data))
	if err != nil {
		return CreateExportResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return CreateExportResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return CreateExportResponse{}, err
	}

	var body CreateExportResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetExport retrieves an export of Audit Log events
func (c *Client) GetExport(ctx context.Context, e GetExportOpts) (GetExportResponse, error) {
	c.once.Do(c.init)

	req, err := http.NewRequest(http.MethodGet, c.ExportsEndpoint+"/"+e.ExportId, nil)
	if err != nil {
		return GetExportResponse{}, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return GetExportResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return GetExportResponse{}, err
	}

	var body GetExportResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

func defaultTime(t time.Time) time.Time {
	if t == (time.Time{}) {
		t = time.Now().UTC()
	}
	return t
}
