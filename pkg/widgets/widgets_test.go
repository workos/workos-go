package widgets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWidgetsGetToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(generateLinkTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedToken := "abc123456"

	token, err := GetToken(context.Background(), GetTokenOpts{
		OrganizationId: "organization_id",
		UserId:         "user_id",
		Scopes:         []WidgetScope{UsersTableManage},
	})

	require.NoError(t, err)
	require.Equal(t, expectedToken, token)
}
