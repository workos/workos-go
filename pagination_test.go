// @oagen-ignore-file

package workos_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v7"
)

func TestIterator_MultiPage(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := requestCount.Add(1)
		if page == 1 {
			w.Write([]byte(`{"data":[{"id":"org_1","name":"Org One"}],"list_metadata":{"before":null,"after":"cursor_1"}}`))
		} else {
			w.Write([]byte(`{"data":[{"id":"org_2","name":"Org Two"}],"list_metadata":{"before":"cursor_1","after":null}}`))
		}
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	iter := client.Organizations().List(context.Background(), &workos.OrganizationsListParams{})

	var items []string
	for iter.Next() {
		items = append(items, iter.Current().ID)
	}
	require.NoError(t, iter.Err())
	require.Equal(t, []string{"org_1", "org_2"}, items)
	require.Equal(t, int32(2), requestCount.Load(), "expected exactly 2 page requests")
}

func TestIterator_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[],"list_metadata":{"before":null,"after":null}}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	iter := client.Organizations().List(context.Background(), &workos.OrganizationsListParams{})

	require.False(t, iter.Next())
	require.NoError(t, iter.Err())
}
