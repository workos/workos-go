// @oagen-ignore-file

package workos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

type listResponse[T any] struct {
	Data         []T          `json:"data"`
	ListMetadata listMetadata `json:"list_metadata"`
}

type listMetadata struct {
	Before *string `json:"before"`
	After  *string `json:"after"`
}

// Iterator provides auto-pagination over list endpoints.
//
// Example usage:
//
//	iter := client.UserManagement().ListUsers(ctx, &workos.UserManagementListUsersParams{})
//	for iter.Next() {
//	    user := iter.Current()
//	    fmt.Println(user.Email)
//	}
//	if err := iter.Err(); err != nil {
//	    log.Fatal(err)
//	}
type Iterator[T any] struct {
	cur      *T
	items    []T
	err      error
	ctx      context.Context
	client   *Client
	method   string
	path     string
	params   any
	cursor   string
	dataPath string
	defaults map[string]string
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
	params any,
	cursor string,
	dataPath string,
	opts []RequestOption,
	defaults map[string]string,
) *Iterator[T] {
	return &Iterator[T]{
		ctx:      ctx,
		client:   client,
		method:   method,
		path:     path,
		params:   params,
		cursor:   cursor,
		dataPath: dataPath,
		defaults: defaults,
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

	params := withCursorAndDefaults(it.params, it.cursor, it.after, it.defaults)

	var rawResp json.RawMessage
	_, err := it.client.request(it.ctx, it.method, it.path, params, nil, &rawResp, it.opts)
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

// Cursor returns the current pagination cursor, which can be used to resume
// iteration across process restarts by passing it as the "after" parameter.
func (it *Iterator[T]) Cursor() *string {
	return it.after
}

func withCursorAndDefaults(params any, cursor string, after *string, defaults map[string]string) any {
	values, err := encodeQuery(params)
	if err != nil {
		if after != nil && cursor != "" {
			v := url.Values{}
			v.Set(cursor, *after)
			return v
		}
		return params
	}
	if values == nil {
		values = url.Values{}
	}
	// Apply spec-level defaults for params the caller hasn't set.
	for k, v := range defaults {
		if values.Get(k) == "" {
			values.Set(k, v)
		}
	}
	if after != nil && cursor != "" {
		values.Set(cursor, *after)
	}
	return values
}
