// @oagen-ignore-file

package workos_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v10"
)

func TestAuditLogsCreateEventOptionalOccurredAt(t *testing.T) {
	for _, timestamp := range []string{"", "2026-11-03T12:34:56.789Z"} {
		name := "omitted"
		if timestamp != "" {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/audit_logs/events", r.URL.Path)
				var body struct {
					OrganizationID string                     `json:"organization_id"`
					Event          map[string]json.RawMessage `json:"event"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				require.Equal(t, "org_test", body.OrganizationID)
				if timestamp == "" {
					require.NotContains(t, body.Event, "occurred_at")
				} else {
					var received string
					require.NoError(t, json.Unmarshal(body.Event["occurred_at"], &received))
					require.Equal(t, timestamp, received)
				}
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(map[string]bool{"success": true}))
			}))
			defer server.Close()

			event := &workos.AuditLogEvent{
				Action:  "user.signed_in",
				Actor:   &workos.AuditLogEventActor{ID: "user_test", Type: "user"},
				Targets: []*workos.AuditLogEventTarget{{ID: "team_test", Type: "team"}},
				Context: &workos.AuditLogEventContext{Location: "192.0.2.1"},
			}
			if timestamp != "" {
				event.OccurredAt = timestamp
			}
			client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
			result, err := client.AuditLogs().CreateEvent(context.Background(), &workos.AuditLogsCreateEventParams{
				OrganizationID: "org_test",
				Event:          event,
			})
			require.NoError(t, err)
			require.True(t, result.Success)
		})
	}
}
