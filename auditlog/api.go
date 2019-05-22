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
	apiKey = ""
)

func init() {
	apiKey = os.Getenv("WORKOS_API_KEY")
}

// SetAPIKey allows you to set the clients API key for all API requests.
func SetAPIKey(key string) {
	apiKey = key
}

// Get executes a get request to a provided resource
func Get(path string) (*http.Response, error) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	endpoint := os.Getenv("WORKOS_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://api.workos.com"
	}

	route := fmt.Sprintf("%s%s", endpoint, path)
	req, err := http.NewRequest("GET", route, nil)
	if err != nil {
		return nil, err
	}

	// Should error if not present
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

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

// ListRequestParams allows you to confire FindAll or List request to paginate
// any entries after & before a given index.
type ListRequestParams struct {
	After  string
	Before string
	Limit  int
}

func (p ListRequestParams) GetStartingAfter() string {
	if p.Before != "" && p.After != "" {
		return ""
	}
	return p.After
}

func (p ListRequestParams) GetEndingBefore() string {
	return p.Before
}

func (p ListRequestParams) GetLimit() int {
	if p.Limit > 1000 {
		return 1000
	}

	if p.Limit <= 0 {
		return 10
	}

	return p.Limit
}

type ListMeta struct {
	HasMore    bool   `json:"has_more"`
	TotalCount uint32 `json:"total_count"`
	URL        string `json:"url"`
}
