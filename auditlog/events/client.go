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

// List returns a list of events.
func List(params auditlog.ListRequestParams) *Iter {
	if params.EndingBefore != "" && params.StartingAfter != "" {
		params.StartingAfter = ""
	}

	return &Iter{auditlog.GetIter(params, func(params auditlog.ListRequestParams) ([]interface{}, auditlog.ListMeta, error) {
		list := auditlog.EventList{}
		list, err := FindAll(params)

		ret := make([]interface{}, len(list.Data))
		for i, v := range list.Data {
			ret[i] = v
		}

		return ret, list.ListMeta, err
	})}
}

// FindAll returns a paginated set of Audit Log entries matching the search
// query.
func FindAll(params auditlog.ListRequestParams) (auditlog.EventList, error) {
	if params.EndingBefore != "" && params.StartingAfter != "" {
		params.StartingAfter = ""
	}

	path := eventsPath

	q := url.Values{}

	limit := params.Limit
	if limit <= 0 {
		limit = 10
	}

	q.Add("limit", strconv.Itoa(params.Limit))
	q.Add("starting_after", params.StartingAfter)
	q.Add("ending_before", params.EndingBefore)

	query := q.Encode()
	if query != "" {
		path = fmt.Sprintf("%s?%s", path, query)
	}

	resp, err := auditlog.Get(path)
	if err != nil {
		return auditlog.EventList{}, err
	}

	defer resp.Body.Close()

	list := auditlog.EventList{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&list)
	if err != nil {
		return auditlog.EventList{}, err
	}

	return list, nil
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

// Iter is an iterator for events.
type Iter struct {
	*auditlog.Iter
}

// Event returns the event which the iterator is currently pointing to.
func (i *Iter) Event() *auditlog.Event {
	return i.Current().(*auditlog.Event)
}
