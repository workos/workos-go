package auditlog

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	eventsPath = "/audit-log/events"
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

// Find looks up a single WorkOS Audit Log event.
func Find(id string) (EventResponse, error) {
	path := fmt.Sprintf("%s/%s", eventsPath, id)
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

// EventsResponse represents a set of Audit Log events returned from WorkOS.
type EventsResponse struct {
	Ok               bool            `json:"ok"`
	Events           []EventResponse `json:"events"`
	ResponseMetadata struct {
		NextCursor     string `json:"next_cursor"`
		PreviousCursor string `json:"previous_cursor"`
	} `json:"response_metadata"`
}

// EventsRequestParams allows you to configure the FindAll request to find
// Audit Log entries after & before a given time or by a specific action.
type EventsRequestParams struct {
	Start  time.Time
	End    time.Time
	Action Action
	Cursor string
	Limit  int
}

// FindAll returns a paginated set of Audit Log entries matching the search
// query.
func FindAll(params EventsRequestParams) (EventsResponse, error) {
	path := eventsPath
	q := url.Values{}

	if params.Limit < 0 || params.Limit <= 1000 {
		params.Limit = 50
	}
	q.Add("limit", strconv.Itoa(params.Limit))

	if !params.Start.IsZero() {
		q.Add("start", params.Start.UTC().Format(time.RFC3339))
	}

	if !params.End.IsZero() {
		q.Add("end", params.End.UTC().Format(time.RFC3339))
	}

	if params.Cursor != "" {
		q.Add("cursor", params.Cursor)
	}

	if params.Action != "" {
		q.Add("action", string(params.Action))
	}

	query := q.Encode()
	if query != "" {
		path = fmt.Sprintf("%s?%s", path, query)
	}

	resp, err := get(path)
	if err != nil {
		return EventsResponse{}, err
	}

	defer resp.Body.Close()

	events := EventsResponse{}
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
