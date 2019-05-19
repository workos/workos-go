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

func TestIterOne(t *testing.T) {
	tq := testQuery{{[]interface{}{1}, ListMeta{}, nil}}
	want := []interface{}{1}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.NoError(t, gerr)
}

func TestIterOneErr(t *testing.T) {
	tq := testQuery{{[]interface{}{1}, ListMeta{}, errTest}}
	want := []interface{}{1}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.Equal(t, errTest, gerr)
}

func TestIterPage2Empty(t *testing.T) {
	tq := testQuery{
		{[]interface{}{&item{"x"}}, ListMeta{HasMore: true, TotalCount: 0, URL: ""}, nil},
		{nil, ListMeta{}, nil},
	}
	want := []interface{}{&item{"x"}}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.NoError(t, gerr)
}

func TestIterPage2EmptyErr(t *testing.T) {
	tq := testQuery{
		{[]interface{}{&item{"x"}}, ListMeta{HasMore: true, TotalCount: 0, URL: ""}, nil},
		{nil, ListMeta{}, errTest},
	}
	want := []interface{}{&item{"x"}}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.Equal(t, errTest, gerr)
}

func TestIterTwoPages(t *testing.T) {
	tq := testQuery{
		{[]interface{}{&item{"x"}}, ListMeta{HasMore: true, TotalCount: 0, URL: ""}, nil},
		{[]interface{}{2}, ListMeta{HasMore: false, TotalCount: 0, URL: ""}, nil},
	}
	want := []interface{}{&item{"x"}, 2}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.NoError(t, gerr)
}

func TestIterTwoPagesErr(t *testing.T) {
	tq := testQuery{
		{[]interface{}{&item{"x"}}, ListMeta{HasMore: true, TotalCount: 0, URL: ""}, nil},
		{[]interface{}{2}, ListMeta{HasMore: false, TotalCount: 0, URL: ""}, errTest},
	}
	want := []interface{}{&item{"x"}, 2}
	g, gerr := collect(GetIter(ListRequestParams{}, tq.query))
	assert.Equal(t, 0, len(tq))
	assert.Equal(t, want, g)
	assert.Equal(t, errTest, gerr)
}

var errTest = errors.New("test error")

type item struct {
	ID string
}

type testQuery []struct {
	v []interface{}
	m ListMeta
	e error
}

func (tq *testQuery) query(ListRequestParams) ([]interface{}, ListMeta, error) {
	x := (*tq)[0]
	*tq = (*tq)[1:]
	return x.v, x.m, x.e
}

func collect(it *Iter) ([]interface{}, error) {
	var g []interface{}
	for it.Next() {
		g = append(g, it.Current())
	}
	return g, it.Err()
}
