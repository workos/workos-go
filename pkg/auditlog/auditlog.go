// Package alog is a package to send audit logs events to WorkOS.
package alog

import (
	"os"
	"time"
)

var (
	// DefaultPublisher is the publisher used by SetAPIKey, Publish and Close
	// functions.
	DefaultPublisher = &Publisher{
		APIKey:    os.Getenv("WORKOS_API_KEY"),
		Endpoint:  "https://api.workos.com/events",
		Retries:   3,
		QueueSize: 512,
	}
)

// Event represents an Audit Log event.
type Event struct {
	Action     string                 `json:"action"`
	ActionType string                 `json:"action_type"`
	ActorName  string                 `json:"actor_name"`
	ActorID    string                 `json:"actor_id"`
	Group      string                 `json:"group"`
	Location   string                 `json:"location"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	OccurredAt time.Time              `json:"occurred_at"`
	TargetName string                 `json:"target_name"`
	TargetID   string                 `json:"target_id"`
}

// SetAPIKey sets the WorkOS API key to use when using Publish.
func SetAPIKey(k string) {
	DefaultPublisher.APIKey = k
}

// Publish publishes the given events.
func Publish(events ...Event) {
	DefaultPublisher.Publish(events...)
}

// Close stops publishings audit log events and releases allocated resources.
// It waits for pending events to be sent before returning.
func Close() {
	DefaultPublisher.Close()
}
