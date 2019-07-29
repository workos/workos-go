package auditlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"time"
)

var (
	alpha = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789"

	// ErrMaximumMetadataProperties is for when an event adds more metadata than
	// WorkOS can support.
	ErrMaximumMetadataProperties = errors.New("exceeded maximum number of properties for metadata")

	// ErrMetadataKeyLength is for when the key for a metadata property exceeds
	// the limit for WorkOS to ingest.
	ErrMetadataKeyLength = errors.New("exceeded 40 character limit for metadata key")

	// ErrMetadataValueLength is for when the value for a metadata property exceeds
	// the limit for WorkOS to ingest.
	ErrMetadataValueLength = errors.New("exceeded 500 character limit for metadata value")
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

// Auditable is an interface to assist in representing how a given struct
// should be represented in the WorkOS Audit Log.
type Auditable interface {
	ToAuditableName() string
	ToAuditableID() string
}

// ActionType is the type that holds the CRUD action used for the WorkOS
// Audit Log.
type ActionType string

const (
	Create ActionType = "C"
	Read   ActionType = "R"
	Update ActionType = "U"
	Delete ActionType = "D"
)

// Event represents the structure of a Audit Log event with all the necessary
// metadata needed to describe an event properly.
type Event struct {
	Group      string     `json:"group"`
	Action     Action     `json:"action"`
	ActionType ActionType `json:"action_type"`
	ActorName  string     `json:"actor_name"`
	ActorID    string     `json:"actor_id"`
	Location   string     `json:"location"`
	OccurredAt time.Time  `json:"occurred_at"`
	TargetName string     `json:"target_name"`
	TargetID   string     `json:"target_id"`

	// TODO: Using interface{} means we can have nested interface{}'s which isn't
	// ideal schema wise. Supporting primitives like string, bool, int, or arrays
	// of primitives is likely fine. Before validations are enforced learn more.
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// A unique key per event to ensure WorkOS does not store the same event more
	// than once.
	idempotencyKey string
}

// NewEvent initializes a new event populated with default information about
// the environment.
func NewEvent(action Action, actionType ActionType) Event {
	location, err := os.Hostname()
	if err != nil {
		location = ""
	}

	return Event{
		idempotencyKey: generateIdempotencyKey(25),
		Action:         action,
		ActionType:     actionType,
		Location:       location,
		OccurredAt:     time.Now().UTC(),
		Metadata:       map[string]interface{}{},
	}
}

// NewEventWithHTTP initializes a new event populated with default information
// about the environment and HTTP request.
func NewEventWithHTTP(action Action, actionType ActionType, r *http.Request) Event {
	event := NewEvent(action, actionType)
	event.SetLocation(r.RemoteAddr)
	metadata := map[string]interface{}{
		"http_method": r.Method,
		"request_url": r.URL.String(),
	}

	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		metadata["user_agent"] = userAgent
	}

	requestID := r.Header.Get("X-Request-ID")
	if requestID != "" {
		metadata["request_id"] = requestID
	}

	event.AddMetadata(metadata)

	return event
}

// NewEventWithMetadata initializes a new event populated with default
// information about the environment with a default of user supplied
// information.
func NewEventWithMetadata(action Action, actionType ActionType, metadata map[string]interface{}) (Event, error) {
	event := NewEvent(action, actionType)
	err := event.AddMetadata(metadata)
	if err != nil {
		return Event{}, err
	}

	return event, nil
}

// SetGroup sets the Event Group based on the provided interface.
func (e *Event) SetGroup(group Auditable) {
	e.Group = group.ToAuditableID()
}

// SetActor sets the Event ActorName and ActorID based on the provided interface.
func (e *Event) SetActor(actor Auditable) {
	e.ActorName = actor.ToAuditableName()
	e.ActorID = actor.ToAuditableID()
}

// SetTarget sets the Event TargetName and TargetID based on the provided interface.
func (e *Event) SetTarget(target Auditable) {
	e.TargetName = target.ToAuditableName()
	e.TargetID = target.ToAuditableID()
}

// SetLocation sets the IPV4, IPV6, or hostname where the Event originated from.
func (e *Event) SetLocation(location string) {
	e.Location = location
}

// AddMetadata adds information to enrich the Audit Log event. Add any
// information you need to properly describe the action being performed.
//
// If a particular bit of metadata surrounding the event may change at any time
// in the future and it is important you can trace what its value at a
// particular time is, you should consider adding it to the event.
func (e Event) AddMetadata(metadata map[string]interface{}) (err error) {
	for k, v := range metadata {
		err = e.addMetadata(k, v)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e Event) addMetadata(key string, value interface{}) error {
	if len(e.Metadata) >= 50 {
		return ErrMaximumMetadataProperties
	}

	if len(key) > 40 {
		return ErrMetadataKeyLength
	}

	// A string was passed, need to make sure it doesn't exceed 500 character limit.
	vs, ok := value.(string)
	if ok && len(vs) > 500 {
		return ErrMetadataValueLength
	}

	// The value implements the Auditable interface and should be expanded.
	if _, ok := value.(Auditable); ok {
		nameKey := fmt.Sprintf("%s_name", key)
		idKey := fmt.Sprintf("%s_id", key)
		e.Metadata[nameKey] = value.(Auditable).ToAuditableName()
		e.Metadata[idKey] = value.(Auditable).ToAuditableID()

		return nil
	}

	e.Metadata[key] = value

	return nil
}

// Publish delivers the event to WorkOS asyncronously.
func (e Event) Publish() chan error {
	// Add the global metadata to the Event's metadata
	for k, v := range globalMetadata {
		e.Metadata[k] = v
	}

	ch := make(chan error, 1)

	// Caller can decide if it wants an async event or sync
	go func() {
		body, err := json.Marshal(e)
		if err != nil {
			ch <- err
			return
		}

		err = e.publishEvent(body)
		ch <- err
	}()

	return ch
}

// PublishEvent delivers the Audit Log event to WorkOS.
func (e Event) publishEvent(body []byte) error {
	// Add retry logic
	// Ensure http.Client connection re-use
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	endpoint := os.Getenv("WORKOS_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://api.workos.com"
	}

	path := fmt.Sprintf("%s%s", endpoint, eventsPath)

	// Depending on size of body, look to encode with zlib
	req, err := http.NewRequest("POST", path, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", e.idempotencyKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(bodyBytes))
	}

	return nil
}

func generateIdempotencyKey(size int) string {
	buffer := make([]byte, size)
	alphaLen := len(alpha)
	for i := 0; i < size; i++ {
		buffer[i] = alpha[rand.Intn(alphaLen)]
	}

	return string(buffer)
}
