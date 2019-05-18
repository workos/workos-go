package auditlog

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	userAgent  = "workos-go/0.1"
	eventsPath = "/events"
)

var (
	ApiKey = ""
)

func init() {
	ApiKey = os.Getenv("WORKOS_API_KEY")
}

// SetAPIKey allows you to set the clients API key for all API requests.
func SetAPIKey(key string) {
	ApiKey = key
}

// Get exucutes a get request to a provided resource
func Get(path string) (*http.Response, error) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	endpoint := os.Getenv("WORKOS_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://max.workos.dev"
	}

	route := fmt.Sprintf("%s%s", endpoint, path)
	req, err := http.NewRequest("GET", route, nil)
	if err != nil {
		return nil, err
	}

	// Should error if not present
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ApiKey))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Received a %d", resp.StatusCode)
	}

	return resp, nil
}

// EventResponse represents an Audit Log event stored in your WorkOS Audit Log.
type EventResponse struct {
	Event

	ID              string `json:"id"`
	Object          string `json:"object"`
	LocationCity    string `json:"location_city"`
	LocationState   string `json:"location_state"`
	LocationCountry string `json:"location_country"`
	AppID           string `json:"app_id"`
}

// EventsResponse represents a set of Audit Log events returned from WorkOS.
type EventsResponse struct {
	Object        string  `json:"object"`
	URL           string  `json:"url"`
	HasMore       bool    `json:"has_more"`
	Data          []Event `json:"data"`
	requestParams EventsRequestParams
}

// EventsRequestParams allows you to configure the FindAll request to find
// any entries after & before a given time or by a specific action.
type EventsRequestParams struct {
	StartingAfter string
	EndingBefore  string
	Limit         int
}
