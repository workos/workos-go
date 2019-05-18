package auditlog

// EventItr represents and iterative event
// TODO: redo this with reflections
type EventItr struct {
	values   []Event
	current  Event
	err      error
	params   EventsRequestParams
	response EventsResponse
	query    func(EventsRequestParams) (EventsResponse, error)
}

// Next returns the next event in the set
func (it *EventItr) Next() bool {
	if len(it.values) == 0 && it.response.HasMore {
		if it.params.StartingAfter != "" {
			it.params.StartingAfter = it.current.ID
		} else {
			it.params.EndingBefore = it.current.ID
		}
		it.getPage()
	}

	if len(it.values) == 0 {
		return false
	}

	it.current = it.values[0]
	it.values = it.values[1:]

	return true
}

// Event returns the current value
func (it EventItr) Event() Event {
	return it.current
}

func (it *EventItr) getPage() {
	it.response, it.err = it.query(it.params)
	it.values = it.response.Data
}

// GetEventItr returns an EventItr with a custom params and query func
func GetEventItr(params EventsRequestParams, query func(EventsRequestParams) (EventsResponse, error)) *EventItr {
	return &EventItr{
		params:   params,
		query:    query,
		response: EventsResponse{HasMore: true},
	}
}
