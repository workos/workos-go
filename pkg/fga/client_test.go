package fga

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
)

func TestGetResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetResourceOpts
		expected Resource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns a Resource",
			client: &Client{
				APIKey: "test",
			},
			options: GetResourceOpts{
				ResourceType: "report",
				ResourceId:   "ljc_1029",
			},
			expected: Resource{
				ResourceType: "report",
				ResourceId:   "ljc_1029",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getResourceTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			resource, err := client.GetResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func getResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(Resource{
		ResourceType: "report",
		ResourceId:   "ljc_1029",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListResources(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListResourcesOpts
		expected ListResourcesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Resources",
			client: &Client{
				APIKey: "test",
			},
			options: ListResourcesOpts{
				ResourceType: "report",
			},

			expected: ListResourcesResponse{
				Data: []Resource{
					{
						ResourceType: "report",
						ResourceId:   "ljc_1029",
					},
					{
						ResourceType: "report",
						ResourceId:   "mso_0806",
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
			server := httptest.NewServer(http.HandlerFunc(listResourcesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			resources, err := client.ListResources(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resources)
		})
	}
}

func listResourcesTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListResourcesResponse
	}{
		ListResourcesResponse: ListResourcesResponse{
			Data: []Resource{
				{
					ResourceType: "report",
					ResourceId:   "ljc_1029",
				},
				{
					ResourceType: "report",
					ResourceId:   "mso_0806",
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

func TestListResourceTypes(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListResourceTypesOpts
		expected ListResourceTypesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns ResourceTypes",
			client: &Client{
				APIKey: "test",
			},
			options: ListResourceTypesOpts{
				Order: "asc",
			},

			expected: ListResourceTypesResponse{
				Data: []ResourceType{
					{
						Type: "report",
						Relations: map[string]interface{}{
							"owner": map[string]interface{}{},
							"editor": map[string]interface{}{
								"inherit_if": "owner",
							},
							"viewer": map[string]interface{}{
								"inherit_if": "editor",
							},
						},
					},
					{
						Type:      "user",
						Relations: map[string]interface{}{},
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
			server := httptest.NewServer(http.HandlerFunc(listResourceTypesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			resourceTypes, err := client.ListResourceTypes(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resourceTypes)
		})
	}
}

func listResourceTypesTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListResourceTypesResponse
	}{
		ListResourceTypesResponse: ListResourceTypesResponse{
			Data: []ResourceType{
				{
					Type: "report",
					Relations: map[string]interface{}{
						"owner": map[string]interface{}{},
						"editor": map[string]interface{}{
							"inherit_if": "owner",
						},
						"viewer": map[string]interface{}{
							"inherit_if": "editor",
						},
					},
				},
				{
					Type:      "user",
					Relations: map[string]interface{}{},
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

func TestBatchUpdateResourceTypes(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  []UpdateResourceTypeOpts
		expected []ResourceType
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns ResourceTypes",
			client: &Client{
				APIKey: "test",
			},
			options: []UpdateResourceTypeOpts{
				{
					Type: "report",
					Relations: map[string]interface{}{
						"owner": map[string]interface{}{},
						"editor": map[string]interface{}{
							"inherit_if": "owner",
						},
						"viewer": map[string]interface{}{
							"inherit_if": "editor",
						},
					},
				},
				{
					Type:      "user",
					Relations: map[string]interface{}{},
				},
			},

			expected: []ResourceType{
				{
					Type: "report",
					Relations: map[string]interface{}{
						"owner": map[string]interface{}{},
						"editor": map[string]interface{}{
							"inherit_if": "owner",
						},
						"viewer": map[string]interface{}{
							"inherit_if": "editor",
						},
					},
				},
				{
					Type:      "user",
					Relations: map[string]interface{}{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(batchUpdateResourceTypesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			resourceTypes, err := client.BatchUpdateResourceTypes(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resourceTypes)
		})
	}
}

func batchUpdateResourceTypesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal([]ResourceType{
		{
			Type: "report",
			Relations: map[string]interface{}{
				"owner": map[string]interface{}{},
				"editor": map[string]interface{}{
					"inherit_if": "owner",
				},
				"viewer": map[string]interface{}{
					"inherit_if": "editor",
				},
			},
		},
		{
			Type:      "user",
			Relations: map[string]interface{}{},
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateResourceOpts
		expected Resource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Resource",
			client: &Client{
				APIKey: "test",
			},
			options: CreateResourceOpts{
				ResourceType: "report",
				ResourceId:   "sso_1710",
			},
			expected: Resource{
				ResourceType: "report",
				ResourceId:   "sso_1710",
			},
		},
		{
			scenario: "Request returns Resource with Metadata",
			client: &Client{
				APIKey: "test",
			},
			options: CreateResourceOpts{
				ResourceType: "report",
				ResourceId:   "sso_1710",
				Meta: map[string]interface{}{
					"description": "Some report",
				},
			},
			expected: Resource{
				ResourceType: "report",
				ResourceId:   "sso_1710",
				Meta: map[string]interface{}{
					"description": "Some report",
				},
			},
		},
		{
			scenario: "Request with no ResourceId returns a Resource with generated report id",
			client: &Client{
				APIKey: "test",
			},
			options: CreateResourceOpts{
				ResourceType: "report",
			},
			expected: Resource{
				ResourceType: "report",
				ResourceId:   "report_1029384756",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createResourceTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			resource, err := client.CreateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func createResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var opts CreateResourceOpts
	json.NewDecoder(r.Body).Decode(&opts)
	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resourceId := "sso_1710"
	if opts.ResourceId == "" {
		resourceId = "report_1029384756"
	}

	body, err := json.Marshal(
		Resource{
			ResourceType: "report",
			ResourceId:   resourceId,
			Meta:         opts.Meta,
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestUpdateResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdateResourceOpts
		expected Resource
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Resource with updated Meta",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateResourceOpts{
				ResourceType: "report",
				ResourceId:   "lad_8812",
				Meta: map[string]interface{}{
					"description": "Updated report",
				},
			},
			expected: Resource{
				ResourceType: "report",
				ResourceId:   "lad_8812",
				Meta: map[string]interface{}{
					"description": "Updated report",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateResourceTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			resource, err := client.UpdateResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resource)
		})
	}
}

func updateResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(
		Resource{
			ResourceType: "report",
			ResourceId:   "lad_8812",
			Meta: map[string]interface{}{
				"description": "Updated report",
			},
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestDeleteResource(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteResourceOpts
		expected error
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Resource",
			client: &Client{
				APIKey: "test",
			},
			options: DeleteResourceOpts{
				ResourceType: "user",
				ResourceId:   "user_01SXW182",
			},
			expected: nil,
		},
		{
			scenario: "Request for non-existent Resource returns error",
			client: &Client{
				APIKey: "test",
			},
			err: true,
			options: DeleteResourceOpts{
				ResourceType: "user",
				ResourceId:   "safgdfgs",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteResourceTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.DeleteResource(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, err)
		})
	}
}

func deleteResourceTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var opts CreateResourceOpts
	json.NewDecoder(r.Body).Decode(&opts)

	var body []byte
	var err error

	if r.URL.Path == "/fga/v1/resources/user/user_01SXW182" {
		body, err = nil, nil
	} else {
		http.Error(w, fmt.Sprintf("%s %s not found", opts.ResourceType, opts.ResourceId), http.StatusNotFound)
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListWarrants(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListWarrantsOpts
		expected ListWarrantsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Warrants",
			client: &Client{
				APIKey: "test",
			},
			options: ListWarrantsOpts{
				ResourceType: "report",
			},

			expected: ListWarrantsResponse{
				Data: []Warrant{
					{
						ResourceType: "report",
						ResourceId:   "ljc_1029",
						Relation:     "member",
						Subject: Subject{
							ResourceType: "user",
							ResourceId:   "user_01SXW182",
						},
					},
					{
						ResourceType: "report",
						ResourceId:   "aut_7403",
						Relation:     "member",
						Subject: Subject{
							ResourceType: "user",
							ResourceId:   "user_01SXW182",
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
			server := httptest.NewServer(http.HandlerFunc(listWarrantsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			resources, err := client.ListWarrants(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, resources)
		})
	}
}

func listWarrantsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListWarrantsResponse
	}{
		ListWarrantsResponse: ListWarrantsResponse{
			Data: []Warrant{
				{
					ResourceType: "report",
					ResourceId:   "ljc_1029",
					Relation:     "member",
					Subject: Subject{
						ResourceType: "user",
						ResourceId:   "user_01SXW182",
					},
				},
				{
					ResourceType: "report",
					ResourceId:   "aut_7403",
					Relation:     "member",
					Subject: Subject{
						ResourceType: "user",
						ResourceId:   "user_01SXW182",
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

func TestWriteWarrant(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  WriteWarrantOpts
		expected WriteWarrantResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request with no op returns WarrantToken",
			client: &Client{
				APIKey: "test",
			},
			options: WriteWarrantOpts{
				ResourceType: "report",
				ResourceId:   "sso_1710",
				Relation:     "member",
				Subject: Subject{
					ResourceType: "user",
					ResourceId:   "user_01SXW182",
				},
			},
			expected: WriteWarrantResponse{
				WarrantToken: "new_warrant_token",
			},
		},
		{
			scenario: "Request with create op returns WarrantToken",
			client: &Client{
				APIKey: "test",
			},
			options: WriteWarrantOpts{
				Op:           WarrantOpCreate,
				ResourceType: "report",
				ResourceId:   "sso_1710",
				Relation:     "member",
				Subject: Subject{
					ResourceType: "user",
					ResourceId:   "user_01SXW182",
				},
			},
			expected: WriteWarrantResponse{
				WarrantToken: "new_warrant_token",
			},
		},
		{
			scenario: "Request with delete op returns WarrantToken",
			client: &Client{
				APIKey: "test",
			},
			options: WriteWarrantOpts{
				Op:           WarrantOpDelete,
				ResourceType: "report",
				ResourceId:   "sso_1710",
				Relation:     "member",
				Subject: Subject{
					ResourceType: "user",
					ResourceId:   "user_01SXW182",
				},
			},
			expected: WriteWarrantResponse{
				WarrantToken: "new_warrant_token",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(writeWarrantTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			warrantResponse, err := client.WriteWarrant(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, warrantResponse)
		})
	}
}

func TestBatchWriteWarrants(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  []WriteWarrantOpts
		expected WriteWarrantResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request with multiple warrants returns WarrantToken",
			client: &Client{
				APIKey: "test",
			},
			options: []WriteWarrantOpts{
				{
					Op:           WarrantOpDelete,
					ResourceType: "report",
					ResourceId:   "sso_1710",
					Relation:     "viewer",
					Subject: Subject{
						ResourceType: "user",
						ResourceId:   "user_01SXW182",
					},
				},
				{
					Op:           WarrantOpCreate,
					ResourceType: "report",
					ResourceId:   "sso_1710",
					Relation:     "editor",
					Subject: Subject{
						ResourceType: "user",
						ResourceId:   "user_01SXW182",
					},
				},
			},
			expected: WriteWarrantResponse{
				WarrantToken: "new_warrant_token",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(writeWarrantTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			warrantResponse, err := client.BatchWriteWarrants(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, warrantResponse)
		})
	}
}

func writeWarrantTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(
		WriteWarrantResponse{
			WarrantToken: "new_warrant_token",
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCheck(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CheckOpts
		expected CheckResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns true check result",
			client: &Client{
				APIKey: "test",
			},
			options: CheckOpts{
				Checks: []WarrantCheck{
					{
						ResourceType: "report",
						ResourceId:   "ljc_1029",
						Relation:     "member",
						Subject: Subject{
							ResourceType: "user",
							ResourceId:   "user_01SXW182",
						},
					},
				},
			},
			expected: CheckResponse{
				Result:     CheckResultAuthorized,
				IsImplicit: false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(checkTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			checkResult, err := client.Check(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, checkResult)
		})
	}
}

func checkTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(
		CheckResponse{
			Result:     CheckResultAuthorized,
			IsImplicit: false,
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCheckBatch(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CheckBatchOpts
		expected []CheckResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns array of check results",
			client: &Client{
				APIKey: "test",
			},
			options: CheckBatchOpts{
				Checks: []WarrantCheck{
					{
						ResourceType: "report",
						ResourceId:   "ljc_1029",
						Relation:     "member",
						Subject: Subject{
							ResourceType: "user",
							ResourceId:   "user_01SXW182",
						},
					},
					{
						ResourceType: "report",
						ResourceId:   "spt_8521",
						Relation:     "member",
						Subject: Subject{
							ResourceType: "user",
							ResourceId:   "user_01SXW182",
						},
					},
				},
			},
			expected: []CheckResponse{
				{
					Result:     CheckResultAuthorized,
					IsImplicit: false,
				},
				{
					Result:     CheckResultNotAuthorized,
					IsImplicit: false,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(checkBatchTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			checkResults, err := client.CheckBatch(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, checkResults)
		})
	}
}

func checkBatchTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(
		[]CheckResponse{
			{
				Result:     CheckResultAuthorized,
				IsImplicit: false,
			},
			{
				Result:     CheckResultNotAuthorized,
				IsImplicit: false,
			},
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestQuery(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  QueryOpts
		expected QueryResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns QueryResults",
			client: &Client{
				APIKey: "test",
			},
			options: QueryOpts{
				Query: "select role where user:user_01SXW182 is member",
			},
			expected: QueryResponse{
				Data: []QueryResult{
					{
						ResourceType: "role",
						ResourceId:   "role_01SXW182",
						Relation:     "member",
						Warrant: Warrant{
							ResourceType: "role",
							ResourceId:   "role_01SXW182",
							Relation:     "member",
							Subject: Subject{
								ResourceType: "user",
								ResourceId:   "user_01SXW182",
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
			server := httptest.NewServer(http.HandlerFunc(queryTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			queryResults, err := client.Query(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, queryResults)
		})
	}
}

func queryTestHandler(w http.ResponseWriter, r *http.Request) {
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
		QueryResponse
	}{
		QueryResponse: QueryResponse{
			Data: []QueryResult{
				{
					ResourceType: "role",
					ResourceId:   "role_01SXW182",
					Relation:     "member",
					Warrant: Warrant{
						ResourceType: "role",
						ResourceId:   "role_01SXW182",
						Relation:     "member",
						Subject: Subject{
							ResourceType: "user",
							ResourceId:   "user_01SXW182",
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
