package organizations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v2/pkg/common"
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
				ID:   "organization_id",
				Name: "Foo Corp",
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

func getOrganizationTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(Organization{
		ID:   "organization_id",
		Name: "Foo Corp",
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
					Organization{
						ID:   "organization_id",
						Name: "Foo Corp",
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
				Organization{
					ID:   "organization_id",
					Name: "Foo Corp",
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
			scenario: "Request returns Organization",
			client: &Client{
				APIKey: "test",
			},
			options: CreateOrganizationOpts{
				Name: "Foo Corp",
			},
			expected: Organization{
				ID:   "organization_id",
				Name: "Foo Corp",
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
	if opts.IdempotencyKey == "duplicate" {
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
			ID:   "organization_id",
			Name: "Foo Corp",
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
			scenario: "Request returns Organization",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateOrganizationOpts{
				Organization: "organization_id",
				Name:         "Foo Corp",
			},
			expected: Organization{
				ID:   "organization_id",
				Name: "Foo Corp",
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

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(
		Organization{
			ID:   "organization_id",
			Name: "Foo Corp",
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
