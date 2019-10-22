// Package alog is a package to send audit logs events to WorkOS.
//
// Example:
//   func main() {
//       alog.SetAPIKey("my_api_key")
//       defer alog.Close()
//
//       // Wherever you need to publish an audit log event:
//       alog.Publish(alog.Event{
//           Action:     "document.viewed",
//           ActionType: "r",
//           ActorName:  "Jairo Kunde",
//           ActorID:    "user_01DGZ0FAXN978HCET66Q98QMTQ",
//           Group:      "abstract.com",
//           Location:   "55.27.223.26",
//           OccurredAt: time.Now(),
//           TargetName: "central.class",
//           TargetID:   "doc_01DGZ0FAXP4HA4X0BVFKS0ZH4Y",
//       })
//   }
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
		QueueSize: 512,
	}

	currentLocation string
)

func init() {
	currentLocation, _ = os.Hostname()
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

	indempotencyKey string
}

func defaultLocation(location string) string {
	if location == "" {
		location = currentLocation
	}
	return location
}
