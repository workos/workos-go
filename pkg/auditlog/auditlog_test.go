package auditlog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAuditLog(t *testing.T) {
	handler := &defaultTestHandler{}
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}

	server := httptest.NewServer(http.HandlerFunc(handlerFunc))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}

	SetAPIKey("test")

	err := Publish(context.TODO(), Event{})
	require.NoError(t, err)
}

func TestMetadataMerge(t *testing.T) {
	a := Metadata{
		"foo":   "bar",
		"while": 42,
	}

	b := Metadata{
		"foo":   "boo",
		"hello": "world",
	}

	a.merge(b)

	require.Len(t, a, 3)
	require.Equal(t, "bar", a["foo"])
	require.Equal(t, 42, a["while"])
	require.Equal(t, "world", a["hello"])
}

func TestMetadataValidate(t *testing.T) {
	oversizedMetada := make(Metadata, 51)
	for i := 0; i < 51; i++ {
		key := uuid.New().String()
		oversizedMetada[key] = struct{}{}
	}

	tests := []struct {
		scenario string
		metadata Metadata
		err      bool
	}{
		{
			scenario: "metadata are valid",
			metadata: Metadata{"foo": "bar"},
		},
		{
			scenario: "metadata with more than 50 keys returns an error",
			metadata: oversizedMetada,
			err:      true,
		},
		{
			scenario: "metadata with a key with more than 40 characters returns an error",
			metadata: Metadata{
				"foo": "bar",
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": struct{}{},
			},
			err: true,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			err := test.metadata.validate()
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
