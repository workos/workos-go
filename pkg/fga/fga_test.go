package fga

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v4/pkg/common"
)

func TestFGAGetObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getObjectTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Object{
		ObjectType: "report",
		ObjectId:   "ljc_1029",
	}
	objectResponse, err := GetObject(context.Background(), GetObjectOpts{
		ObjectType: "report",
		ObjectId:   "ljc_1029",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, objectResponse)
}

func TestFGAListObjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listObjectsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListObjectsResponse{
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
	}
	objectsResponse, err := ListObjects(context.Background(), ListObjectsOpts{
		ObjectType: "report",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, objectsResponse)
}

func TestFGACreateObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(createObjectTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Object{
		ObjectType: "report",
		ObjectId:   "sso_1710",
	}
	createdObject, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "report",
		ObjectId:   "sso_1710",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, createdObject)
}

func TestFGAUpdateObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(updateObjectTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := Object{
		ObjectType: "report",
		ObjectId:   "lad_8812",
		Meta: map[string]interface{}{
			"description": "Updated report",
		},
	}
	updatedObject, err := UpdateObject(context.Background(), UpdateObjectOpts{
		ObjectType: "report",
		ObjectId:   "lad_8812",
		Meta: map[string]interface{}{
			"description": "Updated report",
		},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, updatedObject)
}

func TestFGADeleteObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(deleteObjectTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: "user",
		ObjectId:   "user_01SXW182",
	})

	require.NoError(t, err)
}

func TestFGAListObjectTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listObjectTypesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListObjectTypesResponse{
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
	}
	objectTypesResponse, err := ListObjectTypes(context.Background(), ListObjectTypesOpts{
		Order: "asc",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, objectTypesResponse)
}

func TestFGABatchUpdateObjectTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(batchUpdateObjectTypesTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := []ObjectType{
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
	objectTypes, err := BatchUpdateObjectTypes(context.Background(), []UpdateObjectTypeOpts{
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
	require.Equal(t, expectedResponse, objectTypes)
}

func TestFGAListWarrants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listWarrantsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListWarrantsResponse{
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
	}
	warrantsResponse, err := ListWarrants(context.Background(), ListWarrantsOpts{
		ObjectType: "report",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, warrantsResponse)
}

func TestFGAWriteWarrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(writeWarrantTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := WriteWarrantResponse{
		WarrantToken: "new_warrant_token",
	}
	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "create",
		ObjectType: "report",
		ObjectId:   "sso_1710",
		Relation:   "member",
		Subject: Subject{
			ObjectType: "user",
			ObjectId:   "user_01SXW182",
		},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, warrantResponse)
}

func TestFGABatchWriteWarrants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(writeWarrantTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := WriteWarrantResponse{
		WarrantToken: "new_warrant_token",
	}
	warrantResponse, err := BatchWriteWarrants(context.Background(), []WriteWarrantOpts{
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
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, warrantResponse)
}

func TestFGACheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(checkTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	checkResponse, err := Check(context.Background(), CheckOpts{
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
	})

	require.NoError(t, err)
	require.True(t, checkResponse.Authorized())
}

func TestFGACheckBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(checkBatchTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	checkResponses, err := CheckBatch(context.Background(), CheckBatchOpts{
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
		HTTPClient: server.Client(),
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := QueryResponse{
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
	}
	queryResponse, err := Query(context.Background(), QueryOpts{
		Query: "select role where user:user_01SXW182 is member",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, queryResponse)
}
