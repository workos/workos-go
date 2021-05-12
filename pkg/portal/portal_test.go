package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPortalGenerateLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(generateLinkTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedLink := "https://id.workos.test/portal/launch?secret=1234"

	link, err := GenerateLink(context.Background(), GenerateLinkOpts{
		Intent:       "sso",
		Organization: "organization_id",
		ReturnURL:    "https://foo-corp.app.com/settings",
	})

	require.NoError(t, err)
	require.Equal(t, expectedLink, link)
}
