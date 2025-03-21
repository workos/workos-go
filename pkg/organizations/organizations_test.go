package organizations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
	"github.com/workos/workos-go/v4/pkg/roles"
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
		ID:                               "org_01EHT88Z8J8795GZNQ4ZP1J81T",
		Name:                             "Foo Corp",
		AllowProfilesOutsideOrganization: false,
		Domains: []OrganizationDomain{
			{
				ID:                   "org_domain_01HEJXJSTVEDT7T58BM70FMFET",
				Domain:               "foo-corp.com",
				OrganizationID:       "org_01EHT88Z8J8795GZNQ4ZP1J81T",
				State:                "verified",
				VerificationStrategy: "dns",
				VerificationToken:    "aW5HQ8Sgps1y3LQyrShsFRo3F",
				VerificationPrefix:   "superapp-domain-verification-0fmfet",
			},
		},
		ExternalID: "external_id",
	}
	organizationResponse, err := GetOrganization(context.Background(), GetOrganizationOpts{
		Organization: "org_01EHT88Z8J8795GZNQ4ZP1J81T",
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
			{
				ID:                               "organization_id",
				Name:                             "Foo Corp",
				AllowProfilesOutsideOrganization: false,
				Domains: []OrganizationDomain{
					{
						ID:             "organization_domain_id",
						Domain:         "foo-corp.com",
						OrganizationID: "organization_id",
						State:          "verified",
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
			ID:                               "organization_id",
			Name:                             "Foo Corp",
			AllowProfilesOutsideOrganization: false,
			Domains: []OrganizationDomain{
				{
					ID:             "organization_domain_id",
					Domain:         "foo-corp.com",
					OrganizationID: "organization_id",
					State:          "verified",
				},
			},
		}

	organization, err := CreateOrganization(context.Background(), CreateOrganizationOpts{
		Name:           "Foo Corp",
		Domains:        []string{"foo-corp.com"},
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
			ID:                               "organization_id",
			Name:                             "Foo Corp",
			AllowProfilesOutsideOrganization: false,
			Domains: []OrganizationDomain{
				{
					ID:             "organization_domain_id",
					Domain:         "foo-corp.com",
					OrganizationID: "organization_id",
					State:          "verified",
				},
				{
					ID:             "organization_domain_id_2",
					Domain:         "foo-corp.io",
					OrganizationID: "organization_id",
					State:          "verified",
				},
			},
		}

	organization, err := UpdateOrganization(context.Background(), UpdateOrganizationOpts{
		Organization: "organization_id",
		Name:         "Foo Corp",
		Domains:      []string{"foo-corp.com", "foo-corp.io"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, organization)
}

func TestOrganizationsListOrganizationRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listOrganizationRolesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListOrganizationRolesResponse{
		Data: []roles.Role{
			{
				ID:          "role_01EHWNCE74X7JSDV0X3SZ3KJNY",
				Name:        "Member",
				Slug:        "member",
				Description: "The default role for all users.",
				Type:        roles.Environment,
				CreatedAt:   "2024-12-01T00:00:00.000Z",
				UpdatedAt:   "2024-12-01T00:00:00.000Z",
			},
			{
				ID:          "role_01EHWNCE74X7JSDV0X3SZ3KJSE",
				Name:        "Org. Member",
				Slug:        "org-member",
				Description: "The default role for org. members.",
				Type:        roles.Organization,
				CreatedAt:   "2024-12-02T00:00:00.000Z",
				UpdatedAt:   "2024-12-02T00:00:00.000Z",
			},
		},
	}

	rolesResponse, err := ListOrganizationRoles(context.Background(), ListOrganizationRolesOpts{
		OrganizationID: "organization_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, rolesResponse)
}
