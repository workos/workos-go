package auditlog

import (
	"reflect"
)

// Query is the function used to get a page listing.
type Query func(ListRequestParams) ([]interface{}, ListMeta, error)

// EventItr represents and iterative event
type Iter struct {
	values  []interface{}
	current interface{}
	err     error
	params  ListRequestParams
	meta    ListMeta
	query   Query
}

// Next returns the next event in the set
func (it *Iter) Next() bool {
	if len(it.values) == 0 && it.meta.HasMore {
		if it.params.GetStartingAfter() != "" {
			it.params.StartingAfter = listItemID(it.current)
		} else {
			it.params.EndingBefore = listItemID(it.current)
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

func (it Iter) Current() interface{} {
	return it.current
}

func (it *Iter) getPage() {
	it.values, it.meta, it.err = it.query(it.params)
}

func (it Iter) Err() error {
	return it.err
}

// GetIter returns a new Iter for a given query and its options.
func GetIter(params ListRequestParams, query Query) *Iter {
	iter := &Iter{
		params: params,
		query:  query,
	}

	iter.getPage()

	return iter
}

func listItemID(x interface{}) string {
	return reflect.ValueOf(x).Elem().FieldByName("ID").String()
}
