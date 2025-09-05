package organizations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v5/pkg/common"
	"github.com/workos/workos-go/v5/pkg/roles"
)

func TestGetOrganization(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetOrganizationOpts
		expected Organization
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns an Organization",
			client: &Client{
				APIKey: "test",
			},
			options: GetOrganizationOpts{
				Organization: "organization_id",
			},
			expected: Organization{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getOrganizationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organization, err := client.GetOrganization(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organization)
		})
	}
}

func TestGetOrganizationByExternalID(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetOrganizationByExternalIDOpts
		expected Organization
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns an Organization",
			client: &Client{
				APIKey: "test",
			},
			options: GetOrganizationByExternalIDOpts{
				ExternalID: "external_id",
			},
			expected: Organization{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getOrganizationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organization, err := client.GetOrganizationByExternalID(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organization)
		})
	}
}

func getOrganizationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(Organization{
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
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListOrganizations(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListOrganizationsOpts
		expected ListOrganizationsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Organizations",
			client: &Client{
				APIKey: "test",
			},
			options: ListOrganizationsOpts{
				Domains: []string{"foo-corp.com"},
			},

			expected: ListOrganizationsResponse{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listOrganizationsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organizations, err := client.ListOrganizations(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organizations)
		})
	}
}

func listOrganizationsTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(struct {
		ListOrganizationsResponse
	}{
		ListOrganizationsResponse: ListOrganizationsResponse{
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
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateOrganization(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateOrganizationOpts
		expected Organization
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Organization with Domains",
			client: &Client{
				APIKey: "test",
			},
			options: CreateOrganizationOpts{
				Name:    "Foo Corp",
				Domains: []string{"foo-corp.com"},
			},
			expected: Organization{
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
		{
			scenario: "Request returns Organization with DomainData",
			client: &Client{
				APIKey: "test",
			},
			options: CreateOrganizationOpts{
				Name: "Foo Corp",
				DomainData: []OrganizationDomainData{
					{
						Domain: "foo-corp.com",
						State:  "verified",
					},
				},
			},
			expected: Organization{
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
		{
			scenario: "Request with duplicate Organization Domain returns error",
			client: &Client{
				APIKey: "test",
			},
			err: true,
			options: CreateOrganizationOpts{
				Name:    "Foo Corp",
				Domains: []string{"duplicate.com"},
			},
		},
		{
			scenario: "Idempotency Key with different event payloads returns error",
			client: &Client{
				APIKey: "test",
			},
			err: true,
			options: CreateOrganizationOpts{
				Name:           "New Corp",
				Domains:        []string{"foo-corp.com"},
				IdempotencyKey: "duplicate",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createOrganizationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organization, err := client.CreateOrganization(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organization)
		})
	}
}

func createOrganizationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var opts CreateOrganizationOpts
	json.NewDecoder(r.Body).Decode(&opts)
	for _, domain := range opts.Domains {
		if domain == "duplicate.com" {
			http.Error(w, "duplicate domain", http.StatusConflict)
			return
		}
	}

	if opts.IdempotencyKey == "duplicate" {
		for _, domain := range opts.Domains {
			if domain != "foo-corp.com" {
				http.Error(w, "duplicate idempotency key", http.StatusConflict)
				return
			}
		}
		if opts.Name != "Foo Corp" {
			http.Error(w, "duplicate idempotency key", http.StatusConflict)
			return
		}
	}
	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(
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
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestUpdateOrganization(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdateOrganizationOpts
		expected Organization
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Organization with Domains",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateOrganizationOpts{
				Organization: "organization_id",
				Name:         "Foo Corp",
				Domains:      []string{"foo-corp.com", "foo-corp.io"},
			},
			expected: Organization{
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
			},
		},
		{
			scenario: "Request returns Organization with DomainData",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateOrganizationOpts{
				Organization: "organization_id",
				Name:         "Foo Corp",
				DomainData: []OrganizationDomainData{
					{
						Domain: "foo-corp.com",
						State:  "verified",
					},
					{
						Domain: "foo-corp.io",
						State:  "verified",
					},
				},
			},
			expected: Organization{
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
			},
		},
		{
			scenario: "Request with duplicate Organization Domain returns error",
			client: &Client{
				APIKey: "test",
			},
			err: true,
			options: UpdateOrganizationOpts{
				Organization: "organization_id",
				Name:         "Foo Corp",
				Domains:      []string{"duplicate.com"},
			},
		},
		{
			scenario: "Request returns Organization with metadata",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateOrganizationOpts{
				Organization: "organization_id",
				Name:         "Foo Corp",
				Metadata: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
			expected: Organization{
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
				Metadata: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateOrganizationTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			organization, err := client.UpdateOrganization(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, organization)
		})
	}
}

func updateOrganizationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var opts UpdateOrganizationOpts
	json.NewDecoder(r.Body).Decode(&opts)
	for _, domain := range opts.Domains {
		if domain == "duplicate.com" {
			http.Error(w, "duplicate domain", http.StatusConflict)
			return
		}
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Create response organization with metadata if present in request
	responseOrg := Organization{
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

	// Include metadata in response if it was present in the request
	if opts.Metadata != nil {
		responseOrg.Metadata = opts.Metadata
	}

	body, err := json.Marshal(responseOrg)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListOrganizationRoles(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListOrganizationRolesOpts
		expected ListOrganizationRolesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns list of roles",
			client: &Client{
				APIKey: "test",
			},
			options: ListOrganizationRolesOpts{
				OrganizationID: "organization_id",
			},
			expected: ListOrganizationRolesResponse{
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listOrganizationRolesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			response, err := client.ListOrganizationRoles(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, response)
		})
	}
}

func listOrganizationRolesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(struct {
		ListOrganizationRolesResponse
	}{ListOrganizationRolesResponse{
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
	}})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListOrganizations_UnmarshalSnakeCaseListMetadata(t *testing.T) {
	raw := []byte(`{
        "data": [],
        "list_metadata": { "before": "", "after": "org_abc123" }
    }`)

	var resp ListOrganizationsResponse
	require.NoError(t, json.Unmarshal(raw, &resp))
	require.Equal(t, "org_abc123", resp.ListMetadata.After)
	require.Equal(t, "", resp.ListMetadata.Before)
}
