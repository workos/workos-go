package auditlog

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Auditable is an interface to assist in representing how a given struct
// should be represented in the WorkOS Audit Log.
type Auditable interface {
	ToAuditableName() string
	ToAuditableID() string
}

// Action is the type to represent an Audit Log action name.
type Action string

// Category returns the given action category.
func (a Action) Category() string {
	parts := strings.Split(string(a), ".")
	return parts[0]
}

// Name returns the given action name.
func (a Action) Name() string {
	parts := strings.Split(string(a), ".")
	return parts[1]
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
	Group      string                 `json:"group"`
	Action     Action                 `json:"action"`
	ActionType ActionType             `json:"action_type"`
	ActorName  string                 `json:"actor_name"`
	ActorID    string                 `json:"actor_id"`
	Location   string                 `json:"location"`
	OccuredAt  time.Time              `json:"occured_at"`
	TargetName string                 `json:"target_name"`
	TargetID   string                 `json:"target_id"`
	Metadata   map[string]interface{} `json:"metadata"`
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

// NewHTTPEvent iniitalizes a new event populated with default information about
// the environment and HTTP request.
func NewHTTPEvent(action Action, actionType ActionType, r *http.Request) Event {
	event := NewEvent(action, actionType)
	event.SetLocation(r.RemoteAddr)

	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		event.AddMetadata("user_agent", userAgent)
	}

	requestID := r.Header.Get("X-Request-ID")
	if requestID != "" {
		event.AddMetadata("request_id", requestID)
	}

	event.AddMetadata("request_url", r.URL.String())

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
func (e Event) AddMetadata(key, value string) error {
	if e.Metadata[key] != nil && e.Metadata[key] != value {
		return fmt.Errorf("cannot set event metadata for '%s' to '%s' as it is already '%s'", key, value, e.Metadata[key])
	}

	e.Metadata[key] = value
	return nil
}
