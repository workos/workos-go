package fga

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
	"github.com/workos/workos-go/v4/pkg/retryablehttp"
)

func TestFGAGetResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getResourceTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Resource{
		ResourceType: "report",
		ResourceId:   "ljc_1029",
	}
	resourceResponse, err := GetResource(context.Background(), GetResourceOpts{
		ResourceType: "report",
		ResourceId:   "ljc_1029",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resourceResponse)
}

func TestFGAListResources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listResourcesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListResourcesResponse{
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
	}
	resourcesResponse, err := ListResources(context.Background(), ListResourcesOpts{
		ResourceType: "report",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resourcesResponse)
}

func TestFGACreateResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createResourceTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Resource{
		ResourceType: "report",
		ResourceId:   "sso_1710",
	}
	createdResource, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "report",
		ResourceId:   "sso_1710",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, createdResource)
}

func TestFGAUpdateResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateResourceTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Resource{
		ResourceType: "report",
		ResourceId:   "lad_8812",
		Meta: map[string]interface{}{
			"description": "Updated report",
		},
	}
	updatedResource, err := UpdateResource(context.Background(), UpdateResourceOpts{
		ResourceType: "report",
		ResourceId:   "lad_8812",
		Meta: map[string]interface{}{
			"description": "Updated report",
		},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, updatedResource)
}

func TestFGADeleteResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteResourceTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: "user",
		ResourceId:   "user_01SXW182",
	})

	require.NoError(t, err)
}

func TestFGAListResourceTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listResourceTypesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListResourceTypesResponse{
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
	}
	resourceTypesResponse, err := ListResourceTypes(context.Background(), ListResourceTypesOpts{
		Order: "asc",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resourceTypesResponse)
}

func TestFGABatchUpdateResourceTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(batchUpdateResourceTypesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := []ResourceType{
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
	}
	resourceTypes, err := BatchUpdateResourceTypes(context.Background(), []UpdateResourceTypeOpts{
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

	require.NoError(t, err)
	require.Equal(t, expectedResponse, resourceTypes)
}

func TestFGAListWarrants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listWarrantsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListWarrantsResponse{
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
	}
	warrantsResponse, err := ListWarrants(context.Background(), ListWarrantsOpts{
		ResourceType: "report",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, warrantsResponse)
}

func TestFGAWriteWarrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(writeWarrantTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := WriteWarrantResponse{
		WarrantToken: "new_warrant_token",
	}
	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "create",
		ResourceType: "report",
		ResourceId:   "sso_1710",
		Relation:     "member",
		Subject: Subject{
			ResourceType: "user",
			ResourceId:   "user_01SXW182",
		},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, warrantResponse)
}

func TestFGABatchWriteWarrants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(writeWarrantTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := WriteWarrantResponse{
		WarrantToken: "new_warrant_token",
	}
	warrantResponse, err := BatchWriteWarrants(context.Background(), []WriteWarrantOpts{
		{
			Op:           "delete",
			ResourceType: "report",
			ResourceId:   "sso_1710",
			Relation:     "viewer",
			Subject: Subject{
				ResourceType: "user",
				ResourceId:   "user_01SXW182",
			},
		},
		{
			Op:           "create",
			ResourceType: "report",
			ResourceId:   "sso_1710",
			Relation:     "editor",
			Subject: Subject{
				ResourceType: "user",
				ResourceId:   "user_01SXW182",
			},
		},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, warrantResponse)
}

func TestFGACheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(checkTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	checkResponse, err := Check(context.Background(), CheckOpts{
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
	})

	require.NoError(t, err)
	require.True(t, checkResponse.Authorized())
}

func TestFGACheckWithWarnings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(checkTestHandlerWarnings))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	checkResponse, err := Check(context.Background(), CheckOpts{
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
	})

	require.NoError(t, err)
	require.Len(t, checkResponse.Warnings, 3)

	sort.Slice(checkResponse.Warnings, func(i, j int) bool {
		return checkResponse.Warnings[i].Warning.GetCode() < checkResponse.Warnings[j].Warning.GetCode()
	})

	first := checkResponse.Warnings[0].Warning
	second := checkResponse.Warnings[1].Warning
	third := checkResponse.Warnings[2].Warning

	mw, ok := first.(*MissingContextKeysWarning)
	require.True(t, ok)
	require.ElementsMatch(t, mw.Keys, []string{"user_id", "org_id"})

	fmt.Println(second)
	bw, ok := second.(*BaseWarning)
	require.True(t, ok)
	require.Equal(t, "unknown", bw.Code)

	cw, ok := third.(*ConvertSchemaWarning)
	require.True(t, ok)
	require.Equal(t, "validation_warning", cw.Code)
}

func TestFGACheckBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(checkBatchTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	checkResponses, err := CheckBatch(context.Background(), CheckBatchOpts{
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
	})

	require.NoError(t, err)
	require.Len(t, checkResponses, 2)
	require.True(t, checkResponses[0].Authorized())
	require.False(t, checkResponses[1].Authorized())
}

func TestFGAQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(queryTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := QueryResponse{
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
	}
	queryResponse, err := Query(context.Background(), QueryOpts{
		Query: "select role where user:user_01SXW182 is member",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, queryResponse)
}

func TestFGAQueryWithWarnings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(queryTestHandlerWarnings))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	queryResponse, err := Query(context.Background(), QueryOpts{
		Query: "select role where user:user_01SXW182 is member",
	})

	require.NoError(t, err)
	require.Len(t, queryResponse.Warnings, 3)

	sort.Slice(queryResponse.Warnings, func(i, j int) bool {
		return queryResponse.Warnings[i].Warning.GetCode() < queryResponse.Warnings[j].Warning.GetCode()
	})

	first := queryResponse.Warnings[0].Warning
	second := queryResponse.Warnings[1].Warning
	third := queryResponse.Warnings[2].Warning

	mw, ok := first.(*MissingContextKeysWarning)
	require.True(t, ok)
	require.ElementsMatch(t, mw.Keys, []string{"user_id", "org_id"})

	bw, ok := second.(*BaseWarning)
	require.True(t, ok)
	require.Equal(t, "unknown", bw.Code)

	cw, ok := third.(*ConvertSchemaWarning)
	require.True(t, ok)
	require.Equal(t, "validation_warning", cw.Code)
}

func TestFGAConvertSchemaToResourceTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(convertSchemaToResourceTypesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ConvertSchemaResponse{
		Version: "0.1",
		ResourceTypes: []ResourceType{
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
		},
	}
	convertedSchema, err := ConvertSchemaToResourceTypes(context.Background(), ConvertSchemaToResourceTypesOpts{
		Schema: "version 0.1\n\ntype report\n    relation owner []\n    relation editor []\n    relation viewer []\n    \n    inherit editor if\n        relation owner\n        \n    inherit viewer if\n        relation editor",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, convertedSchema)
}

func TestFGAConvertResourceTypesToSchema(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(convertResourceTypesToSchemaTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedSchema := "version 0.1\n\ntype report\n    relation owner []\n    relation editor []\n    relation viewer []\n    \n    inherit editor if\n        relation owner\n        \n    inherit viewer if\n        relation editor"
	expectedResponse := ConvertSchemaResponse{
		Version: "0.1",
		Schema:  &expectedSchema,
	}
	convertedSchema, err := ConvertResourceTypesToSchema(context.Background(), ConvertResourceTypesToSchemaOpts{
		ResourceTypes: []ResourceType{
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
		},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, convertedSchema)
}

func TestFGAGetSchema(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getSchemaHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := GetSchemaResponse{
		Version: "0.3",
		ResourceTypes: []ResourceType{
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
					"admin": map[string]interface{}{
						"inherit_if": "viewer",
					},
					"policy": map[string]interface{}{
						"policy": "policy_1",
					},
				},
			},
		},
		Policies: map[string]Policy{
			"policy_1": {
				Name:       "policy_1",
				Language:   "expr",
				Expression: "true",
				Parameters: []PolicyParameter{
					{
						Name: "param_1",
						Type: "string",
					},
				},
			},
		},
	}
	schemaResponse, err := GetSchema(context.Background())

	require.NoError(t, err)
	require.Equal(t, expectedResponse, schemaResponse)
}

func TestFGAUpdateSchema(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getSchemaHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := GetSchemaResponse{
		Version: "0.3",
		ResourceTypes: []ResourceType{
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
					"admin": map[string]interface{}{
						"inherit_if": "viewer",
					},
					"policy": map[string]interface{}{
						"policy": "policy_1",
					},
				},
			},
		},
		Policies: map[string]Policy{
			"policy_1": {
				Name:       "policy_1",
				Language:   "expr",
				Expression: "true",
				Parameters: []PolicyParameter{
					{
						Name: "param_1",
						Type: "string",
					},
				},
			},
		},
	}
	schemaResponse, err := UpdateSchema(context.Background(), UpdateSchemaOpts{
		ResourceTypes: []UpdateResourceTypeOpts{
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
					"admin": map[string]interface{}{
						"inherit_if": "viewer",
					},
					"policy": map[string]interface{}{
						"policy": "policy_1",
					},
				},
			},
		},
		Policies: map[string]UpdatePolicyOpts{
			"policy_1": {
				Name:       "policy_1",
				Language:   "expr",
				Expression: "true",
				Parameters: []PolicyParameter{
					{
						Name: "param_1",
						Type: "string",
					},
				},
			},
		},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, schemaResponse)
}
