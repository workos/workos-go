package organizations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v2/pkg/common"
)

func TestOrganizationsGetOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getOrganizationTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Organization{
		ID:   "organization_id",
		Name: "Foo Corp",
	}
	organizationResponse, err := GetOrganization(context.Background(), GetOrganizationOpts{
		Organization: "organization_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, organizationResponse)
}

func TestOrganizationsListOrganizations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listOrganizationsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListOrganizationsResponse{
		Data: []Organization{
			Organization{
				ID:   "organization_id",
				Name: "Foo Corp",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}

	organizationsResponse, err := ListOrganizations(context.Background(), ListOrganizationsOpts{
		Domains: []string{"foo-corp.com"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, organizationsResponse)
}

func TestOrganizationsCreateOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createOrganizationTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse :=
		Organization{
			ID:   "organization_id",
			Name: "Foo Corp",
		}

	organization, err := CreateOrganization(context.Background(), CreateOrganizationOpts{
		Name:           "Foo Corp",
		IdempotencyKey: "duplicate",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, organization)
}

func TestOrganizationsUpdateOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateOrganizationTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse :=
		Organization{
			ID:   "organization_id",
			Name: "Foo Corp",
		}

	organization, err := UpdateOrganization(context.Background(), UpdateOrganizationOpts{
		Organization: "organization_id",
		Name:         "Foo Corp",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, organization)
}
