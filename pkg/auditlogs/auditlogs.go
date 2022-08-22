// Package `auditlogs` provides a client wrapping the WorkOS Audit Trail API.
//
// Example:
//
//	func main() {
//	    auditlogs.SetAPIKey("my_api_key")
//
//	    // Wherever you need to publish an audit trail event:
//	    err := auditlogs.Publish(context.Background(), auditlogs.AuditLog{
//	        Action:     "document.viewed",
//	        ActionType: auditlogs.Create,
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
func CreateEvent(ctx context.Context, e AuditLogEventOpts) error {
	return DefaultClient.CreateEvent(ctx, e)
}

// CreateEvent creates the given event.
func CreateExport(ctx context.Context, e CreateExportOpts) (CreateExportResponse, error) {
	return DefaultClient.CreateExport(ctx, e)
}

// CreateEvent creates the given event.
func GetExport(ctx context.Context, e GetExportOpts) (GetExportResponse, error) {
	return DefaultClient.GetExport(ctx, e)
}
