package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos-inc/workos-go/pkg/common"
)

func TestPortalListOrganizations(t *testing.T) {
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
				Domains: []OrganizationDomain{
					OrganizationDomain{
						ID:     "organization_domain_id",
						Domain: "foo-corp.com",
					},
				},
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

func TestPortalCreateOrganizations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createOrganizationsTestHandler))
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
			Domains: []OrganizationDomain{
				OrganizationDomain{
					ID:     "organization_domain_id",
					Domain: "foo-corp.com",
				},
			},
		}

	organization, err := CreateOrganization(context.Background(), CreateOrganizationsOpts{
		Name:    "Foo Corp",
		Domains: []string{"foo-corp.com"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, organization)
}

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
