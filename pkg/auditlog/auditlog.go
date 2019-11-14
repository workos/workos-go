// Package auditlog is a package to send audit logs events to WorkOS.
//
// Example:
//   func main() {
//       auditlog.SetAPIKey("my_api_key")
//
//       // Wherever you need to publish an audit log event:
//       err := auditlog.Publish(context.Background(), auditlog.Event{
//           Action:     "document.viewed",
//           ActionType: auditlog.Create,
//           ActorName:  "Jairo Kunde",
//           ActorID:    "user_01DGZ0FAXN978HCET66Q98QMTQ",
//           Group:      "abstract.com",
//           Location:   "55.27.223.26",
//           OccurredAt: time.Now(),
//           TargetName: "central.class",
//           TargetID:   "doc_01DGZ0FAXP4HA4X0BVFKS0ZH4Y",
//       })
//       if err != nil {
//           // Handle error.
//       }
//   }
package auditlog

import (
	"context"
	"os"
	"time"

	"github.com/google/uuid"
)

var (
	// DefaultPublisher is the publisher used by SetAPIKey, Publish and Close
	// functions.
	DefaultPublisher = &Publisher{
		APIKey:   os.Getenv("WORKOS_API_KEY"),
		Endpoint: "https://api.workos.com/events",
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

// Publish publishes the given event.
func Publish(ctx context.Context, e Event) error {
	return DefaultPublisher.Publish(ctx, e)
}

// Event represents an Audit Log event.
type Event struct {
	Action         string                 `json:"action"`
	ActionType     ActionType             `json:"action_type"`
	ActorName      string                 `json:"actor_name"`
	ActorID        string                 `json:"actor_id"`
	Group          string                 `json:"group"`
	IdempotencyKey string                 `json:"-"`
	Location       string                 `json:"location"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	OccurredAt     time.Time              `json:"occurred_at"`
	TargetName     string                 `json:"target_name"`
	TargetID       string                 `json:"target_id"`
}

// ActionType is the type that holds the CRUD action used for the WorkOS Audit
// Log.
type ActionType string

// Constants that enumerate the different action types.
const (
	Create ActionType = "C"
	Read   ActionType = "R"
	Update ActionType = "U"
	Delete ActionType = "D"
)

func defaultLocation(location string) string {
	if location == "" {
		location = currentLocation
	}
	return location
}

func defaultTime(t time.Time) time.Time {
	if t == (time.Time{}) {
		t = time.Now().UTC()
	}
	return t
}

func defaultIdempotencyKey(key string) string {
	if key == "" {
		return uuid.New().String()
	}
	return key
}
