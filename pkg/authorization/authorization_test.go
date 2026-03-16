package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestSetAPIKey(t *testing.T) {
	DefaultClient = &Client{}
	SetAPIKey("test-key-123")
	require.Equal(t, "test-key-123", DefaultClient.APIKey)
}

func TestAuthorizationGetResourceByExternalId(t *testing.T) {
	response := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
		ExternalId:       "my-document-1",
		Name:             "My Document",
		Description:      "A test document",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-01T00:00:00.000Z",
	}

	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, response)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	resource, err := GetResourceByExternalId(context.Background(), GetResourceByExternalIdOpts{
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		ResourceTypeSlug: "document",
		ExternalId:       "my-document-1",
	})
	require.NoError(t, err)
	require.Equal(t, "rsrc_01H945H0YD4F97JN3MNHBFPG37", resource.Id)
	require.Equal(t, "my-document-1", resource.ExternalId)
}

func TestAuthorizationUpdateResourceByExternalId(t *testing.T) {
	var capturedBody map[string]interface{}

	response := AuthorizationResource{
		Object:           "authorization_resource",
		Id:               "rsrc_01H945H0YD4F97JN3MNHBFPG37",
		ExternalId:       "my-document-1",
		Name:             "Updated Document",
		Description:      "Updated description",
		ResourceTypeSlug: "document",
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		CreatedAt:        "2024-01-01T00:00:00.000Z",
		UpdatedAt:        "2024-01-02T00:00:00.000Z",
	}

	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(&capturedBody, nil, response)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	newName := "Updated Document"
	newDescription := "Updated description"
	resource, err := UpdateResourceByExternalId(context.Background(), UpdateResourceByExternalIdOpts{
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		ResourceTypeSlug: "document",
		ExternalId:       "my-document-1",
		Name:             &newName,
		Description:      &newDescription,
	})
	require.NoError(t, err)
	require.Equal(t, "Updated Document", resource.Name)
}

func TestAuthorizationDeleteResourceByExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, nil)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteResourceByExternalId(context.Background(), DeleteResourceByExternalIdOpts{
		OrganizationId:   "org_01H945H0YD4F97JN3MNHBFPG37",
		ResourceTypeSlug: "document",
		ExternalId:       "my-document-1",
	})
	require.NoError(t, err)
}
