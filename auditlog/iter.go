package auditlog

type Iterable interface {
	GetID() string
}

// IterableQuery is the function used to get a page listing.
type IterableQuery func(ListRequestParams) ([]Iterable, ListMeta, error)

// Itr provides a convenient interface for reading a list of interfaces. It stops when there are no more interfaces to iterate over.
type Iter struct {
	values  []Iterable
	current Iterable
	err     error
	params  ListRequestParams
	meta    ListMeta
	query   IterableQuery
}

// Next returns the next value in the set
func (it *Iter) Next() bool {
	if len(it.values) == 0 && it.meta.HasMore {
		if it.params.GetAfter() != "" {
			it.params.After = it.current.GetID()
		} else {
			it.params.Before = it.current.GetID()
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

// Current returns the current Iterable object
func (it Iter) Current() Iterable {
	return it.current
}

// Err returns the error the iterable reports.
func (it Iter) Err() error {
	return it.err
}

// GetIter returns a new Iter for a given query and its options.
func GetIter(params ListRequestParams, query IterableQuery) *Iter {
	iter := &Iter{
		params: params,
		query:  query,
	}

	iter.getPage()

	return iter
}

func (it *Iter) getPage() {
	it.values, it.meta, it.err = it.query(it.params)
}
