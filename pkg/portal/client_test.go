package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateLink(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GenerateLinkOpts
		expected string
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns link with sso intent",
			client: &Client{
				APIKey: "test",
			},
			options: GenerateLinkOpts{
				Intent:       SSO,
				Organization: "organization_id",
				ReturnURL:    "https://foo-corp.app.com/settings",
			},
			expected: "https://id.workos.test/portal/launch?secret=1234",
		},
		{
			scenario: "Request returns link with dsync intent",
			client: &Client{
				APIKey: "test",
			},
			options: GenerateLinkOpts{
				Intent:       DSync,
				Organization: "organization_id",
				ReturnURL:    "https://foo-corp.app.com/settings",
			},
			expected: "https://id.workos.test/portal/launch?secret=1234",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(generateLinkTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			link, err := client.GenerateLink(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, link)
		})
	}
}

func generateLinkTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(struct {
		generateLinkResponse
	}{generateLinkResponse{Link: "https://id.workos.test/portal/launch?secret=1234"}})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
