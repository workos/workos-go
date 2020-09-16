package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos-inc/workos-go/pkg/common"
)

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
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
