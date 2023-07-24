// Package `audittrail` provides a client wrapping the WorkOS Audit Trail API.
//
// Example:
//
//	func main() {
//	    audittrail.SetAPIKey("my_api_key")
//
//	    // Wherever you need to publish an audit trail event:
//	    err := audittrail.Publish(context.Background(), audittrail.EventOpts{
//	        Action:     "document.viewed",
//	        ActionType: audittrail.Create,
//	        ActorName:  "Jairo Kunde",
//	        ActorID:    "user_01DGZ0FAXN978HCET66Q98QMTQ",
//	        Group:      "abstract.com",
//	        Location:   "55.27.223.26",
//	        OccurredAt: time.Now(),
//	        TargetName: "central.class",
//	        TargetID:   "doc_01DGZ0FAXP4HA4X0BVFKS0ZH4Y",
//	    })
//	    if err != nil {
//	        // Handle error.
//	    }
//	}
package audittrail

import (
	"context"
	"errors"
)

var (
	// DefaultClient is the client used by SetAPIKey and Publish functions.
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com/events",
	}

	// GlobalMetadata are metadata that are injected in every audit trail events.
	GlobalMetadata Metadata

	errTooMuchMetadataKeys = errors.New("too much metadata key")
)

// SetAPIKey sets the WorkOS API key to use when using Publish.
func SetAPIKey(k string) {
	DefaultClient.APIKey = k
}

// Publish publishes the given event.
func Publish(ctx context.Context, e EventOpts) error {
	return DefaultClient.Publish(ctx, e)
}

// ListEvents fetches Audit Trail events.
func ListEvents(ctx context.Context, opts ListEventsOpts) (ListEventsResponse, error) {
	return DefaultClient.ListEvents(ctx, opts)
}
