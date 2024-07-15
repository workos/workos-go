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

func TestGetObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  GetObjectOpts
		expected Object
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns an Object",
			client: &Client{
				APIKey: "test",
			},
			options: GetObjectOpts{
				ObjectType: "report",
				ObjectId:   "ljc_1029",
			},
			expected: Object{
				ObjectType: "report",
				ObjectId:   "ljc_1029",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(getObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			object, err := client.GetObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, object)
		})
	}
}

func getObjectTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(Object{
		ObjectType: "report",
		ObjectId:   "ljc_1029",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListObjects(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListObjectsOpts
		expected ListObjectsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Objects",
			client: &Client{
				APIKey: "test",
			},
			options: ListObjectsOpts{
				ObjectType: "report",
			},

			expected: ListObjectsResponse{
				Data: []Object{
					{
						ObjectType: "report",
						ObjectId:   "ljc_1029",
					},
					{
						ObjectType: "report",
						ObjectId:   "mso_0806",
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
			server := httptest.NewServer(http.HandlerFunc(listObjectsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			objects, err := client.ListObjects(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func listObjectsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListObjectsResponse
	}{
		ListObjectsResponse: ListObjectsResponse{
			Data: []Object{
				{
					ObjectType: "report",
					ObjectId:   "ljc_1029",
				},
				{
					ObjectType: "report",
					ObjectId:   "mso_0806",
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

func TestListObjectTypes(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ListObjectTypesOpts
		expected ListObjectTypesResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns ObjectTypes",
			client: &Client{
				APIKey: "test",
			},
			options: ListObjectTypesOpts{
				Order: "asc",
			},

			expected: ListObjectTypesResponse{
				Data: []ObjectType{
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
			server := httptest.NewServer(http.HandlerFunc(listObjectTypesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			objectTypes, err := client.ListObjectTypes(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objectTypes)
		})
	}
}

func listObjectTypesTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListObjectTypesResponse
	}{
		ListObjectTypesResponse: ListObjectTypesResponse{
			Data: []ObjectType{
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

func TestBatchUpdateObjectTypes(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  []UpdateObjectTypeOpts
		expected []ObjectType
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns ObjectTypes",
			client: &Client{
				APIKey: "test",
			},
			options: []UpdateObjectTypeOpts{
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

			expected: []ObjectType{
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
			server := httptest.NewServer(http.HandlerFunc(batchUpdateObjectTypesTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			objectTypes, err := client.BatchUpdateObjectTypes(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objectTypes)
		})
	}
}

func batchUpdateObjectTypesTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := json.Marshal([]ObjectType{
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

func TestCreateObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateObjectOpts
		expected Object
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Object",
			client: &Client{
				APIKey: "test",
			},
			options: CreateObjectOpts{
				ObjectType: "report",
				ObjectId:   "sso_1710",
			},
			expected: Object{
				ObjectType: "report",
				ObjectId:   "sso_1710",
			},
		},
		{
			scenario: "Request returns Object with Metadata",
			client: &Client{
				APIKey: "test",
			},
			options: CreateObjectOpts{
				ObjectType: "report",
				ObjectId:   "sso_1710",
				Meta: map[string]interface{}{
					"description": "Some report",
				},
			},
			expected: Object{
				ObjectType: "report",
				ObjectId:   "sso_1710",
				Meta: map[string]interface{}{
					"description": "Some report",
				},
			},
		},
		{
			scenario: "Request with no ObjectId returns an Object with generated report",
			client: &Client{
				APIKey: "test",
			},
			options: CreateObjectOpts{
				ObjectType: "report",
			},
			expected: Object{
				ObjectType: "report",
				ObjectId:   "report_1029384756",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			object, err := client.CreateObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, object)
		})
	}
}

func createObjectTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var opts CreateObjectOpts
	json.NewDecoder(r.Body).Decode(&opts)
	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	objectId := "sso_1710"
	if opts.ObjectId == "" {
		objectId = "report_1029384756"
	}

	body, err := json.Marshal(
		Object{
			ObjectType: "report",
			ObjectId:   objectId,
			Meta:       opts.Meta,
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestUpdateObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  UpdateObjectOpts
		expected Object
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Object with updated Meta",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateObjectOpts{
				ObjectType: "report",
				ObjectId:   "lad_8812",
				Meta: map[string]interface{}{
					"description": "Updated report",
				},
			},
			expected: Object{
				ObjectType: "report",
				ObjectId:   "lad_8812",
				Meta: map[string]interface{}{
					"description": "Updated report",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(updateObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			object, err := client.UpdateObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, object)
		})
	}
}

func updateObjectTestHandler(w http.ResponseWriter, r *http.Request) {
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
		Object{
			ObjectType: "report",
			ObjectId:   "lad_8812",
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

func TestDeleteObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteObjectOpts
		expected error
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns Object",
			client: &Client{
				APIKey: "test",
			},
			options: DeleteObjectOpts{
				ObjectType: "user",
				ObjectId:   "user_01SXW182",
			},
			expected: nil,
		},
		{
			scenario: "Request for non-existent Object returns error",
			client: &Client{
				APIKey: "test",
			},
			err: true,
			options: DeleteObjectOpts{
				ObjectType: "user",
				ObjectId:   "safgdfgs",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			err := client.DeleteObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, err)
		})
	}
}

func deleteObjectTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	var opts CreateObjectOpts
	json.NewDecoder(r.Body).Decode(&opts)

	var body []byte
	var err error

	if r.URL.Path == "/fga/v1/objects/user/user_01SXW182" {
		body, err = nil, nil
	} else {
		http.Error(w, fmt.Sprintf("%s %s not found", opts.ObjectType, opts.ObjectId), http.StatusNotFound)
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
				ObjectType: "report",
			},

			expected: ListWarrantsResponse{
				Data: []Warrant{
					{
						ObjectType: "report",
						ObjectId:   "ljc_1029",
						Relation:   "member",
						Subject: Subject{
							ObjectType: "user",
							ObjectId:   "user_01SXW182",
						},
					},
					{
						ObjectType: "report",
						ObjectId:   "aut_7403",
						Relation:   "member",
						Subject: Subject{
							ObjectType: "user",
							ObjectId:   "user_01SXW182",
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

			objects, err := client.ListWarrants(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
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
					ObjectType: "report",
					ObjectId:   "ljc_1029",
					Relation:   "member",
					Subject: Subject{
						ObjectType: "user",
						ObjectId:   "user_01SXW182",
					},
				},
				{
					ObjectType: "report",
					ObjectId:   "aut_7403",
					Relation:   "member",
					Subject: Subject{
						ObjectType: "user",
						ObjectId:   "user_01SXW182",
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
				ObjectType: "report",
				ObjectId:   "sso_1710",
				Relation:   "member",
				Subject: Subject{
					ObjectType: "user",
					ObjectId:   "user_01SXW182",
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
				Op:         "create",
				ObjectType: "report",
				ObjectId:   "sso_1710",
				Relation:   "member",
				Subject: Subject{
					ObjectType: "user",
					ObjectId:   "user_01SXW182",
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
				Op:         "delete",
				ObjectType: "report",
				ObjectId:   "sso_1710",
				Relation:   "member",
				Subject: Subject{
					ObjectType: "user",
					ObjectId:   "user_01SXW182",
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
					Op:         "delete",
					ObjectType: "report",
					ObjectId:   "sso_1710",
					Relation:   "viewer",
					Subject: Subject{
						ObjectType: "user",
						ObjectId:   "user_01SXW182",
					},
				},
				{
					Op:         "create",
					ObjectType: "report",
					ObjectId:   "sso_1710",
					Relation:   "editor",
					Subject: Subject{
						ObjectType: "user",
						ObjectId:   "user_01SXW182",
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

func TestCheckMany(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CheckManyOpts
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
			options: CheckManyOpts{
				Checks: []WarrantCheck{
					{
						ObjectType: "report",
						ObjectId:   "ljc_1029",
						Relation:   "member",
						Subject: Subject{
							ObjectType: "user",
							ObjectId:   "user_01SXW182",
						},
					},
				},
			},
			expected: CheckResponse{
				Code:       200,
				Result:     "Authorized",
				IsImplicit: false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(checkManyTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			checkResult, err := client.CheckMany(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, checkResult)
		})
	}
}

func checkManyTestHandler(w http.ResponseWriter, r *http.Request) {
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
			Code:       200,
			Result:     "Authorized",
			IsImplicit: false,
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestBatchCheck(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  BatchCheckOpts
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
			options: BatchCheckOpts{
				Warrants: []WarrantCheck{
					{
						ObjectType: "report",
						ObjectId:   "ljc_1029",
						Relation:   "member",
						Subject: Subject{
							ObjectType: "user",
							ObjectId:   "user_01SXW182",
						},
					},
					{
						ObjectType: "report",
						ObjectId:   "spt_8521",
						Relation:   "member",
						Subject: Subject{
							ObjectType: "user",
							ObjectId:   "user_01SXW182",
						},
					},
				},
			},
			expected: []CheckResponse{
				{
					Code:       200,
					Result:     "Authorized",
					IsImplicit: false,
				},
				{
					Code:       403,
					Result:     "Not Authorized",
					IsImplicit: false,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(batchCheckTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = server.Client()

			checkResults, err := client.BatchCheck(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, checkResults)
		})
	}
}

func batchCheckTestHandler(w http.ResponseWriter, r *http.Request) {
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
				Code:       200,
				Result:     "Authorized",
				IsImplicit: false,
			},
			{
				Code:       403,
				Result:     "Not Authorized",
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
						ObjectType: "role",
						ObjectId:   "role_01SXW182",
						Relation:   "member",
						Warrant: Warrant{
							ObjectType: "role",
							ObjectId:   "role_01SXW182",
							Relation:   "member",
							Subject: Subject{
								ObjectType: "user",
								ObjectId:   "user_01SXW182",
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
					ObjectType: "role",
					ObjectId:   "role_01SXW182",
					Relation:   "member",
					Warrant: Warrant{
						ObjectType: "role",
						ObjectId:   "role_01SXW182",
						Relation:   "member",
						Subject: Subject{
							ObjectType: "user",
							ObjectId:   "user_01SXW182",
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
