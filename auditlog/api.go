package auditlog

import (
	"os"
)

const (
	userAgent  = "workos-go/0.1"
	eventsPath = "/events"
)

var (
	apiKey = ""
)

func init() {
	apiKey = os.Getenv("WORKOS_API_KEY")
}

// SetAPIKey allows you to set the clients API key for all API requests.
func SetAPIKey(key string) {
	apiKey = key
}
