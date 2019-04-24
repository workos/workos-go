package auditlog

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	EventsPath = "/audit-log/events"
)

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

type EventRequestResponse struct {
	Ok               bool            `json:"ok"`
	Events           []EventResponse `json:"events"`
	ResponseMetadata struct {
		NextCursor     string `json:"next_cursor"`
		PreviousCursor string `json:"previous_cursor"`
	} `json:"response_metadata"`
}

// Find looks up a single WorkOS Audit Log event.
func Find(id string) (EventResponse, error) {
	path := fmt.Sprintf("%s/%s", EventsPath, id)
	resp, err := get(path)
	if err != nil {
		return EventResponse{}, err
	}
	defer resp.Body.Close()

	event := EventResponse{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&event)
	if err != nil {
		return EventResponse{}, err
	}

	return event, nil
}

type EventRequestParams struct {
	Start  string
	End    string
	Action Action
}

func FindAll(params EventRequestParams) (EventRequestResponse, error) {
	resp, err := get(EventsPath)
	if err != nil {
		return EventRequestResponse{}, err
	}

	defer resp.Body.Close()

	events := EventRequestResponse{}
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&events)

	return events, nil
}

func get(path string) (*http.Response, error) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	endpoint := os.Getenv("WORKOS_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:4567"
	}

	route := fmt.Sprintf("%s%s", endpoint, path)
	req, err := http.NewRequest("GET", route, nil)
	if err != nil {
		return nil, err
	}

	// Should error if not present
	apiKey := os.Getenv("WORKOS_API_KEY")
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
