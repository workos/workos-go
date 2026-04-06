package workos

import (
	"context"
	"encoding/json"
	"fmt"
)

type listParams interface{}

type listResponse[T any] struct {
	Data         []T          `json:"data"`
	ListMetadata listMetadata `json:"list_metadata"`
}

type listMetadata struct {
	Before *string `json:"before"`
	After  *string `json:"after"`
}

// Iterator provides auto-pagination over list endpoints.
type Iterator[T any] struct {
	cur      *T
	items    []T
	err      error
	ctx      context.Context
	client   *Client
	method   string
	path     string
	params   listParams
	dataPath string
	opts     []RequestOption
	after    *string
	done     bool
	index    int
}

func newIterator[T any](
	ctx context.Context,
	client *Client,
	method string,
	path string,
	params listParams,
	dataPath string,
	opts []RequestOption,
) *Iterator[T] {
	return &Iterator[T]{
		ctx:      ctx,
		client:   client,
		method:   method,
		path:     path,
		params:   params,
		dataPath: dataPath,
		opts:     opts,
	}
}

// Next advances the iterator. Returns false when done or on error.
func (it *Iterator[T]) Next() bool {
	if it.err != nil || it.done {
		return false
	}

	// Return next item from current page
	if it.index < len(it.items) {
		it.cur = &it.items[it.index]
		it.index++
		return true
	}

	// Fetch next page
	if it.after == nil && it.index > 0 {
		it.done = true
		return false
	}

	var rawResp json.RawMessage
	_, err := it.client.request(it.ctx, it.method, it.path, it.params, &rawResp, it.opts)
	if err != nil {
		it.err = err
		return false
	}

	var page listResponse[T]
	if err := json.Unmarshal(rawResp, &page); err != nil {
		it.err = fmt.Errorf("workos: failed to decode page: %w", err)
		return false
	}

	it.items = page.Data
	it.index = 0
	it.after = page.ListMetadata.After

	if len(it.items) == 0 {
		it.done = true
		return false
	}

	it.cur = &it.items[it.index]
	it.index++
	return true
}

// Current returns the current item.
func (it *Iterator[T]) Current() *T {
	return it.cur
}

// Err returns any error from the last page fetch.
func (it *Iterator[T]) Err() error {
	return it.err
}
