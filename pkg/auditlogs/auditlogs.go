// Package `auditlogs` provides a client wrapping the WorkOS Audit Logs API.
//
// Example:
//
//	func main() {
//	    auditlogs.SetAPIKey("my_api_key")
//
//	    // Wherever you need to publish an audit log event:
//	    err := auditlogs.CreateEvent(context.Background(), auditlogs.CreateEventOpts{
//	        OrganizationID: "org_8899300049990088",
//			Event: Event{
//				Action: "team.created",
//				Actor: Actor{
//					ID:   "o5fdfsdfUMCAuunNN3Iwfs34gMw",
//					Name: "jonatas",
//					Type: "user",
//					Metadata: map[string]interface{}{
//						"Email": "person@workos.com",
//					},
//				},
//				Context: Context{
//					Location: "79.226.116.209",
//				},
//				Targets: []Target{
//					Target{ID: "team_123", Type: "team"},
//				},
//			},
//			// IdempotencyKey is optional - SDK will auto-generate if not provided
//			// IdempotencyKey: "your-custom-key",
//	    })
//	    if err != nil {
//	        // Handle error.
//	    }
//	}
package auditlogs

import (
	"context"
)

var (
	// DefaultClient is the client used by SetAPIKey and Publish functions.
	DefaultClient = &Client{
		EventsEndpoint:  "https://api.workos.com/audit_logs/events",
		ExportsEndpoint: "https://api.workos.com/audit_logs/exports",
	}
)

// SetAPIKey sets the WorkOS API key to use when using Publish.
func SetAPIKey(k string) {
	DefaultClient.APIKey = k
}

// CreateEvent creates the given event.
func CreateEvent(ctx context.Context, e CreateEventOpts) error {
	return DefaultClient.CreateEvent(ctx, e)
}

// CreateEvent creates the given event.
func CreateExport(ctx context.Context, e CreateExportOpts) (AuditLogExport, error) {
	return DefaultClient.CreateExport(ctx, e)
}

// CreateEvent creates the given event.
func GetExport(ctx context.Context, e GetExportOpts) (AuditLogExport, error) {
	return DefaultClient.GetExport(ctx, e)
}
