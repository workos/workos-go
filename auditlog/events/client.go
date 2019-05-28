package events

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/workos-inc/workos-go/auditlog"
)

const (
	eventsPath = "/events"
)

// List returns a list of events.
func List(params auditlog.ListRequestParams) *Iter {
	return &Iter{auditlog.GetIter(params, func(params auditlog.ListRequestParams) ([]auditlog.Iterable, auditlog.ListMeta, error) {
		list, err := FindAll(params)

		ret := make([]auditlog.Iterable, len(list.Data))
		for i, v := range list.Data {
			ret[i] = v
		}

		return ret, list.ListMeta, err
	})}
}

// FindAll returns a paginated set of Audit Log entries matching the search
// query.
func FindAll(params auditlog.ListRequestParams) (EventList, error) {
	path := eventsPath
	q := url.Values{}

	q.Add("limit", strconv.Itoa(params.GetLimit()))
	if params.GetBefore() != "" {
		q.Add("after", params.GetAfter())
	}
	q.Add("before", params.GetBefore())

	query := q.Encode()
	if query != "" {
		path = fmt.Sprintf("%s?%s", path, query)
	}

	resp, err := auditlog.Get(path)
	if err != nil {
		return EventList{}, err
	}
	defer resp.Body.Close()

	list := EventList{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&list)
	if err != nil {
		return EventList{}, err
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
func (i *Iter) Event() *auditlog.EventResponse {
	return i.Current().(*auditlog.EventResponse)
}

// EventList represents a set of Audit Log events returned from WorkOS.
type EventList struct {
	auditlog.ListMeta
	Data []auditlog.EventResponse `json:"data"`
}
