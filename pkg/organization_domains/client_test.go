package organization_domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetDomain(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetOrganizationDomainOpts
		expected OrganizationDomain
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns an Organization Domain",
			client: &Client{
				APIKey: "test",
			},
			options: GetOrganizationDomainOpts{
				DomainID: "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
			},
			expected: OrganizationDomain{
				ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
				Domain:               "example.com",
				OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
				State:                "verified",
				VerificationStrategy: "dns",
				VerificationToken:    "token123",
				VerificationPrefix:   "workos-verify",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getDomainTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			domain, err := client.GetDomain(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, domain)
		})
	}
}

func getDomainTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(OrganizationDomain{
		ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
		Domain:               "example.com",
		OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
		State:                "verified",
		VerificationStrategy: "dns",
		VerificationToken:    "token123",
		VerificationPrefix:   "workos-verify",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateDomain(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateOrganizationDomainOpts
		expected OrganizationDomain
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request creates an Organization Domain",
			client: &Client{
				APIKey: "test",
			},
			options: CreateOrganizationDomainOpts{
				OrganizationID: "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
				Domain:         "example.com",
			},
			expected: OrganizationDomain{
				ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
				Domain:               "example.com",
				OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
				State:                "pending",
				VerificationStrategy: "dns",
				VerificationToken:    "token123",
				VerificationPrefix:   "workos-verify",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createDomainTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			domain, err := client.CreateDomain(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, domain)
		})
	}
}

func createDomainTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(OrganizationDomain{
		ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
		Domain:               "example.com",
		OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
		State:                "pending",
		VerificationStrategy: "dns",
		VerificationToken:    "token123",
		VerificationPrefix:   "workos-verify",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestVerifyDomain(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  VerifyOrganizationDomainOpts
		expected OrganizationDomain
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request verifies an Organization Domain",
			client: &Client{
				APIKey: "test",
			},
			options: VerifyOrganizationDomainOpts{
				DomainID: "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
			},
			expected: OrganizationDomain{
				ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
				Domain:               "example.com",
				OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
				State:                "verified",
				VerificationStrategy: "dns",
				VerificationToken:    "token123",
				VerificationPrefix:   "workos-verify",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(verifyDomainTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			domain, err := client.VerifyDomain(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, domain)
		})
	}
}

func verifyDomainTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(OrganizationDomain{
		ID:                   "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
		Domain:               "example.com",
		OrganizationID:       "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
		State:                "verified",
		VerificationStrategy: "dns",
		VerificationToken:    "token123",
		VerificationPrefix:   "workos-verify",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestDeleteDomain(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteOrganizationDomainOpts
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request deletes an Organization Domain",
			client: &Client{
				APIKey: "test",
			},
			options: DeleteOrganizationDomainOpts{
				DomainID: "org_domain_01EHWNCE74X7JSDV0X3SZ3KJNY",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteDomainTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.DeleteDomain(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func deleteDomainTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
