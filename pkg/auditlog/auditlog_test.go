package auditlog

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditLog(t *testing.T) {
	var wg sync.WaitGroup

	handler := &defaultTestHandler{}
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		wg.Done()
	}

	server := httptest.NewServer(http.HandlerFunc(handlerFunc))
	defer server.Close()

	DefaultPublisher = &Publisher{
		Client:   server.Client(),
		Endpoint: server.URL,
		Log:      t.Logf,
	}

	SetAPIKey("test")
	defer Close()

	wg.Add(1)
	Publish(Event{})

	wg.Wait()
	require.Equal(t, 1, handler.requests)
	require.Equal(t, 0, handler.errors)
}
