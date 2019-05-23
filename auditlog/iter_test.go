package auditlog

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIterEmpty(t *testing.T) {
	tq := testQuery{{nil, ListMeta{}, nil}}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, 0, len(g))
	assert.NoError(t, gerr)
}

func TestIterEmptyErr(t *testing.T) {
	tq := testQuery{{nil, ListMeta{}, errTest}}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, 0, len(g))
	assert.Equal(t, errTest, gerr)
}

func TestIterPage2Empty(t *testing.T) {
	tq := testQuery{
		{[]Iterable{&item{"x"}}, ListMeta{HasMore: true, TotalCount: 0, URL: ""}, nil},
		{nil, ListMeta{}, nil},
	}
	want := []Iterable{&item{"x"}}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.NoError(t, gerr)
}

func TestIterPage2EmptyErr(t *testing.T) {
	tq := testQuery{
		{[]Iterable{&item{"x"}}, ListMeta{HasMore: true, TotalCount: 0, URL: ""}, nil},
		{nil, ListMeta{}, errTest},
	}
	want := []Iterable{&item{"x"}}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.Equal(t, errTest, gerr)
}

var errTest = errors.New("test error")

type item struct {
	ID string
}

func (i item) GetID() string {
	return i.ID
}

type testQuery []struct {
	v []Iterable
	m ListMeta
	e error
}

func (tq *testQuery) query(ListRequestParams) ([]Iterable, ListMeta, error) {
	x := (*tq)[0]
	*tq = (*tq)[1:]
	return x.v, x.m, x.e
}

func collect(it *Iter) ([]Iterable, error) {
	var g []Iterable
	for it.Next() {
		g = append(g, it.Current())
	}
	return g, it.Err()
}
