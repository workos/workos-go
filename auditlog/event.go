package auditlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dewski/workos/client"
)

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
	OccuredAt  time.Time  `json:"occured_at"`
	TargetName string     `json:"target_name"`
	TargetID   string     `json:"target_id"`

	// TODO: Using interface{} means we can have nested interface{}'s which isn't
	// ideal schema wise. Supporting primitives like string, bool, int, or arrays
	// of primitives is likely fine. Before validations are enforced learn more.
	Metadata map[string]interface{} `json:"metadata"`
}

// NewEvent initializes a new event populated with default information about
// the environment.
func NewEvent(action Action, actionType ActionType) Event {
	location, err := os.Hostname()
	if err != nil {
		location = ""
	}

	return Event{
		Group:      os.Getenv("WORKOS_GROUP"),
		Action:     action,
		ActionType: actionType,
		Location:   location,
		OccuredAt:  time.Now().UTC(),
		Metadata:   map[string]interface{}{},
	}
}

// NewEventWithHTTP iniitalizes a new event populated with default information
// about the environment and HTTP request.
func NewEventWithHTTP(action Action, actionType ActionType, r *http.Request) Event {
	event := NewEvent(action, actionType)
	event.SetLocation(r.RemoteAddr)
	event.AddMetadata("http_method", r.Method)
	event.AddMetadata("request_url", r.URL.String())

	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		event.AddMetadata("user_agent", userAgent)
	}

	requestID := r.Header.Get("X-Request-ID")
	if requestID != "" {
		event.AddMetadata("request_id", requestID)
	}

	return event
}

// NewEventWithMetadata initializes a new event populated with default
// information about the environment with a default of user supplied
// information.
func NewEventWithMetadata(action Action, actionType ActionType, metadata map[string]interface{}) Event {
	event := NewEvent(action, actionType)
	event.Metadata = metadata
	return event
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
func (e Event) AddMetadata(key string, value interface{}) error {
	if len(e.Metadata) >= 500 {
		return errors.New("attempted to add over 500 properties to metadata, ignoring")
	}

	if globalMetadata[key] != nil {
		return fmt.Errorf("SetMetadata has already set a value for '%s'", key)
	}

	e.Metadata[key] = value

	return nil
}

// Publish delivers the event to WorkOS.
func (e Event) Publish() error {
	for k, v := range globalMetadata {
		e.Metadata[k] = v
	}

	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return client.PublishEvent(body)
}
