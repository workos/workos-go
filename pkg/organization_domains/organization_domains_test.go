package organization_domains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrganizationDomainsGetDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getDomainTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := OrganizationDomain{
		ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
		Domain:               "example.com",
		OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
		State:                "verified",
		VerificationStrategy: "dns",
		VerificationToken:    "token123",
		VerificationPrefix:   "workos-verify",
	}

	domain, err := GetOrganizationDomain(context.Background(), GetOrganizationDomainOpts{
		DomainID: "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, domain)
}

func TestOrganizationDomainsCreateDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createDomainTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := OrganizationDomain{
		ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
		Domain:               "example.com",
		OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
		State:                "pending",
		VerificationStrategy: "dns",
		VerificationToken:    "token123",
		VerificationPrefix:   "workos-verify",
	}

	domain, err := CreateOrganizationDomain(context.Background(), CreateOrganizationDomainOpts{
		OrganizationID: "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
		Domain:         "example.com",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, domain)
}

func TestOrganizationDomainsVerifyDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(verifyDomainTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := OrganizationDomain{
		ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
		Domain:               "example.com",
		OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
		State:                "verified",
		VerificationStrategy: "dns",
		VerificationToken:    "token123",
		VerificationPrefix:   "workos-verify",
	}

	domain, err := VerifyOrganizationDomain(context.Background(), VerifyOrganizationDomainOpts{
		DomainID: "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, domain)
}

func TestOrganizationDomainsDeleteDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteDomainTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteOrganizationDomain(context.Background(), DeleteOrganizationDomainOpts{
		DomainID: "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
	})

	require.NoError(t, err)
}
