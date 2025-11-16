package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

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
			scenario: "Request returns ListObjectsResponse",
			client: &Client{
				APIKey: "test",
			},

			expected: ListObjectsResponse{
				Data: []ObjectDigest{
					{
						Name:      "secret-key",
						Id:        "secret_1029",
						UpdatedAt: time.Unix(0, 0).UTC(),
					},
					{
						Name:      "access-key",
						Id:        "secret_0806",
						UpdatedAt: time.Unix(0, 0).UTC(),
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
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

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
			Data: []ObjectDigest{
				{
					Name:      "secret-key",
					Id:        "secret_1029",
					UpdatedAt: time.Unix(0, 0).UTC(),
				},
				{
					Name:      "access-key",
					Id:        "secret_0806",
					UpdatedAt: time.Unix(0, 0).UTC(),
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

func TestCreateObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateObjectOpts
		expected ObjectMetadata
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns ObjectMetadata",
			client: &Client{
				APIKey: "test",
			},
			options: CreateObjectOpts{
				Name:  "access-key",
				Value: "sensitive-value",
				KeyContext: map[string]interface{}{
					"organization_id": "org_abc123",
				},
			},

			expected: ObjectMetadata{
				Id:        "secret_1029",
				KeyId:     "123e4567-e89b-12d3-a456-426655440000",
				UpdatedAt: time.Unix(0, 0).UTC(),
				Context: map[string]interface{}{
					"organization_id": "org_abc123",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.CreateObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func createObjectTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var createOpts CreateObjectOpts
	err = json.Unmarshal(reqBody, &createOpts)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(
		ObjectMetadata{
			Id:        "secret_1029",
			KeyId:     "123e4567-e89b-12d3-a456-426655440000",
			UpdatedAt: time.Unix(0, 0).UTC(),
			Context:   createOpts.KeyContext,
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestListObjectVersions(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ReadObjectOpts
		expected ListObjectVersionsResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns ListObjectVersionsResponse",
			client: &Client{
				APIKey: "test",
			},
			options: ReadObjectOpts{
				Id: "secret_9876",
			},

			expected: ListObjectVersionsResponse{
				Data: []ObjectVersion{
					{
						Id:             "00000b",
						CreatedAt:      time.Unix(1, 0).UTC(),
						CurrentVersion: false,
					},
					{
						Id:             "00000a",
						CreatedAt:      time.Unix(0, 0).UTC(),
						CurrentVersion: true,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(listObjectVersionsTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.ListObjectVersions(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func listObjectVersionsTestHandler(w http.ResponseWriter, r *http.Request) {
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
		ListObjectVersionsResponse
	}{
		ListObjectVersionsResponse: ListObjectVersionsResponse{
			Data: []ObjectVersion{
				{
					Id:             "00000b",
					CreatedAt:      time.Unix(1, 0).UTC(),
					CurrentVersion: false,
				},
				{
					Id:             "00000a",
					CreatedAt:      time.Unix(0, 0).UTC(),
					CurrentVersion: true,
				},
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

func TestReadObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ReadObjectOpts
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
			options: ReadObjectOpts{
				Id: "secret_9876",
			},

			expected: Object{
				Id:    "secret_9876",
				Name:  "secret-access-key",
				Value: "my secret value",
				Metadata: ObjectMetadata{
					Id:        "secret_9876",
					UpdatedAt: time.Unix(0, 0).UTC(),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(readObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.ReadObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func readObjectTestHandler(w http.ResponseWriter, r *http.Request) {
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
		Object
	}{
		Object: Object{
			Id:    "secret_9876",
			Name:  "secret-access-key",
			Value: "my secret value",
			Metadata: ObjectMetadata{
				Id:        "secret_9876",
				UpdatedAt: time.Unix(0, 0).UTC(),
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

func TestDescribeObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  ReadObjectOpts
		expected Object
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
			options: ReadObjectOpts{
				Id: "secret_9876",
			},

			expected: Object{
				Id:   "secret_9876",
				Name: "secret-access-key",
				Metadata: ObjectMetadata{
					Id:        "secret_9876",
					UpdatedAt: time.Unix(0, 0).UTC(),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(describeObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.DescribeObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func describeObjectTestHandler(w http.ResponseWriter, r *http.Request) {
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
		Object
	}{
		Object: Object{
			Id:   "secret_9876",
			Name: "secret-access-key",
			Metadata: ObjectMetadata{
				Id:        "secret_9876",
				UpdatedAt: time.Unix(0, 0).UTC(),
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
			scenario: "Request returns Object",
			client: &Client{
				APIKey: "test",
			},
			options: UpdateObjectOpts{
				Id:    "secret_1029",
				Value: "even more sensitive value",
			},

			expected: Object{
				Id:   "secret_1029",
				Name: "secret-access-key",
				Metadata: ObjectMetadata{
					Id:        "secret_1029",
					KeyId:     "123e4567-e89b-12d3-a456-426655440000",
					UpdatedAt: time.Unix(0, 0).UTC(),
					Context: map[string]interface{}{
						"organization_id": "org_abc123",
					},
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
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.UpdateObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
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
			Id:   "secret_1029",
			Name: "secret-access-key",
			Metadata: ObjectMetadata{
				Id:        "secret_1029",
				KeyId:     "123e4567-e89b-12d3-a456-426655440000",
				UpdatedAt: time.Unix(0, 0).UTC(),
				Context: map[string]interface{}{
					"organization_id": "org_abc123",
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

func TestDeleteObject(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DeleteObjectOpts
		expected DeleteObjectResponse
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns DeleteObjectResponse",
			client: &Client{
				APIKey: "test",
			},
			options: DeleteObjectOpts{
				Id: "secret_9876",
			},

			expected: DeleteObjectResponse{
				Success: true,
				Name:    "secret-access-key",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(deleteObjectTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.DeleteObject(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func deleteObjectTestHandler(w http.ResponseWriter, r *http.Request) {
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
		DeleteObjectResponse
	}{
		DeleteObjectResponse: DeleteObjectResponse{
			Success: true,
			Name:    "secret-access-key",
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestCreateDataKey(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  CreateDataKeyOpts
		expected DataKeyPair
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns DataKeyPair",
			client: &Client{
				APIKey: "test",
			},
			options: CreateDataKeyOpts{
				KeyContext: map[string]interface{}{
					"organization_id": "org_abc123",
				},
			},

			expected: DataKeyPair{
				Id:            "secret_1029",
				DataKey:       "aaaaaaaaaaaaaaaaa",
				EncryptedKeys: "bajsbdnioasndpoasjdopasjdomas",
				KeyContext: map[string]interface{}{
					"organization_id": "org_abc123",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(createDataKeyTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.CreateDataKey(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func createDataKeyTestHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer test" {
		http.Error(w, "bad auth", http.StatusUnauthorized)
		return
	}

	if userAgent := r.Header.Get("User-Agent"); !strings.Contains(userAgent, "workos-go/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var createOpts CreateDataKeyOpts
	err = json.Unmarshal(reqBody, &createOpts)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(
		DataKeyPair{
			Id:            "secret_1029",
			DataKey:       "aaaaaaaaaaaaaaaaa",
			EncryptedKeys: "bajsbdnioasndpoasjdopasjdomas",
			KeyContext:    createOpts.KeyContext,
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestDecryptDataKey(t *testing.T) {
	tests := []struct {
		scenario string
		client   *Client
		options  DecryptDataKeyOpts
		expected DataKey
		err      bool
	}{
		{
			scenario: "Request without API Key returns an error",
			client:   &Client{},
			err:      true,
		},
		{
			scenario: "Request returns DataKey",
			client: &Client{
				APIKey: "test",
			},
			options: DecryptDataKeyOpts{
				Keys: "bajsbdnioasndpoasjdopasjdomas",
			},

			expected: DataKey{
				Id:  "secret_1029",
				Key: "aaaaaaaaaaaaaaaaa",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(decryptDataKeyTestHandler))
			defer server.Close()

			client := test.client
			client.Endpoint = server.URL
			client.HTTPClient = &retryablehttp.HttpClient{Client: *server.Client()}

			objects, err := client.DecryptDataKey(context.Background(), test.options)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expected, objects)
		})
	}
}

func decryptDataKeyTestHandler(w http.ResponseWriter, r *http.Request) {
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
		DataKey{
			Id:  "secret_1029",
			Key: "aaaaaaaaaaaaaaaaa",
		})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
