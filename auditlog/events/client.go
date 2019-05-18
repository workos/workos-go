package events

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/workos-inc/workos-go/auditlog"
)

const (
	userAgent  = "workos-go/0.1"
	eventsPath = "/events"
)

// List returns an iteration given a parameter
func List(params auditlog.EventsRequestParams) *auditlog.EventItr {
	return auditlog.GetEventItr(params, FindAll)
}

// FindAll returns a paginated set of Audit Log entries matching the search
// query.
func FindAll(params auditlog.EventsRequestParams) (auditlog.EventsResponse, error) {
	path := eventsPath
	q := url.Values{}

	q.Add("limit", strconv.Itoa(params.Limit))
	q.Add("starting_after", params.StartingAfter)
	q.Add("ending_before", params.EndingBefore)

	query := q.Encode()
	if query != "" {
		path = fmt.Sprintf("%s?%s", path, query)
	}

	resp, err := auditlog.Get(path)
	if err != nil {
		return auditlog.EventsResponse{}, err
	}

	defer resp.Body.Close()

	eventResponse := auditlog.EventsResponse{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&eventResponse)
	if err != nil {
		return auditlog.EventsResponse{}, err
	}
	return eventResponse, nil
}

// Find looks up a single WorkOS Audit Log event.
func Find(id string) (auditlog.EventResponse, error) {
	path := fmt.Sprintf("%s/%s", eventsPath, id)
	resp, err := auditlog.Get(path)
	if err != nil {
		return auditlog.EventResponse{}, err
	}
	defer resp.Body.Close()

	event := auditlog.EventResponse{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&event)
	if err != nil {
		return auditlog.EventResponse{}, err
	}

	return event, nil
}
