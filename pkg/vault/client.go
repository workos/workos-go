package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v4/internal/workos"
	"github.com/workos/workos-go/v4/pkg/common"
	"github.com/workos/workos-go/v4/pkg/retryablehttp"
	"github.com/workos/workos-go/v4/pkg/workos_errors"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Order represents the order of records.
type Order string

// Constants that enumerate the available orders.
const (
	Asc  Order = "asc"
	Desc Order = "desc"
)

// Client represents a client that performs Vault requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to get Vault records from WorkOS.
	// Defaults to http.Client.
	HTTPClient *retryablehttp.HttpClient

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &retryablehttp.HttpClient{Client: http.Client{Timeout: 10 * time.Second}}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

type KeyContext map[string]interface{}

// Objects
type ObjectMetadata struct {
	// Unique string ID of the object.
	Id string `json:"id"`

	// ID of the WorkOS environment where the object was created.
	EnvironmentId string `json:"environment_id"`

	// ID of the key used to encrypt the object.
	KeyId string `json:"key_id"`

	// ID of the specific version of the object.
	VersionId string `json:"version_id"`

	// Map of values used to determine the encryption key used.
	Context KeyContext `json:"context"`

	// ISO 8601 timestamp of the last modification to the object.
	UpdatedAt time.Time `json:"updated_at"`

	UpdatedBy struct {
		// ID of the user or API key that last wrote to the object.
		Id string `json:"id"`

		// Name of the user or API key that last wrote to the object.
		Name string `json:"name"`
	} `json:"updated_by"`
}

type Object struct {
	// Unique string ID of the object.
	Id string `json:"id"`

	// Unique name of the object, used as the KV store key.
	Name string `json:"name"`

	// Plaintext data that will be stored in an encrypted format.
	Value string `json:"value"`

	// Extra information about the object.
	Metadata ObjectMetadata `json:"metadata"`
}

type ObjectDigest struct {
	// Unique string ID of the object.
	Id string `json:"id"`

	// Unique name of the object, used as the KV store key.
	Name string `json:"name"`

	// ISO 8601 timestamp of the last modification to the object.
	UpdatedAt time.Time `json:"updated_at"`
}

type ListObjectsOpts struct {
	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Object ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Object ID.
	After string `url:"after,omitempty"`
}

type ListObjectsResponse struct {
	// List of stored Objects.
	Data []ObjectDigest `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type CreateObjectOpts struct {
	// Unique name of the object, used as the KV store key.
	Name string `json:"name"`

	// Plaintext data that will be stored in an encrypted format.
	Value string `json:"value"`

	// Map of values used to determine the encryption key used.
	KeyContext KeyContext `json:"key_context"`
}

type ReadObjectOpts struct {
	// Unique string ID of the object.
	Id string `json:"id"`
}

type ObjectVersion struct {
	// ID of the specific version of the object.
	Id string `json:"id"`

	// ISO 8601 timestamp of when the version was created.
	CreatedAt time.Time `json:"created_at"`

	// Indicator of whether this is the active, default version.
	CurrentVersion bool `json:"current_version"`
}

type ListObjectVersionsResponse struct {
	// List of verions for an encrypted Object.
	Data []ObjectVersion `json:"data"`
}

type UpdateObjectOpts struct {
	// Unique string ID of the object.
	Id string `json:"id"`

	// Plaintext data that will be stored in an encrypted format.
	Value string `json:"value"`

	// ID of the expected version of the object.
	VersionCheck string `json:"version_check,omitempty"`
}

type DeleteObjectOpts struct {
	// Unique string ID of the object.
	Id string `json:"id"`

	// ID of the expected version of the object.
	VersionCheck string `json:"version_check,omitempty"`
}

type DeleteObjectResponse struct {
	// Indicator of whether the operation succeeded.
	Success bool `json:"success"`

	// Unique name of the object, used as the KV store key.
	Name string `json:"name"`
}

type DataKeyPair struct {
	// Map of values used to determine the encryption key used.
	KeyContext KeyContext `json:"context"`

	// Unique ID of the data key.
	Id string `json:"id"`

	// Base64 encoded data key that can be used for encryption operations.
	DataKey string `json:"data_key"`

	// An encrypted, Base64 encoded data key.
	EncryptedKeys string `json:"encrypted_keys"`
}

type DataKey struct {
	// Unique ID of the data key.
	Id string `json:"id"`

	// Base64 encoded data key that can be used for encryption operations.
	Key string `json:"data_key"`
}

type CreateDataKeyOpts struct {
	// Map of values used to determine the encryption key used.
	KeyContext KeyContext `json:"context"`
}

type DecryptDataKeyOpts struct {
	// An encrypted, Base64 encoded data key.
	Keys string `json:"keys"`
}

// ListObjects gets a list of Vault Objects.
func (c *Client) ListObjects(ctx context.Context, opts ListObjectsOpts) (ListObjectsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/vault/v1/kv", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListObjectsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	if opts.Order == "" {
		opts.Order = Desc
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListObjectsResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListObjectsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListObjectsResponse{}, err
	}

	var body ListObjectsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// CreateObject creates a new encrypted Object in Vault.
func (c *Client) CreateObject(ctx context.Context, opts CreateObjectOpts) (ObjectMetadata, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return ObjectMetadata{}, err
	}

	endpoint := fmt.Sprintf("%s/vault/v1/kv", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return ObjectMetadata{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ObjectMetadata{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ObjectMetadata{}, err
	}

	var body ObjectMetadata
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListObjectVersions gets a list of versions for a single Vault Object.
func (c *Client) ListObjectVersions(ctx context.Context, opts ReadObjectOpts) (ListObjectVersionsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/vault/v1/kv/%s/versions", c.Endpoint, opts.Id)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListObjectVersionsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListObjectVersionsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListObjectVersionsResponse{}, err
	}

	var body ListObjectVersionsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ReadObject gets an Object with its decrypted value.
func (c *Client) ReadObject(ctx context.Context, opts ReadObjectOpts) (Object, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/vault/v1/kv/%s", c.Endpoint, opts.Id)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Object{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Object{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Object{}, err
	}

	var body Object
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DescribeObject gets metadata about an object, withthout the value.
func (c *Client) DescribeObject(ctx context.Context, opts ReadObjectOpts) (Object, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/vault/v1/kv/%s/metadata", c.Endpoint, opts.Id)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Object{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Object{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Object{}, err
	}

	var body Object
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateObject write a new value for an existing Object.
func (c *Client) UpdateObject(ctx context.Context, opts UpdateObjectOpts) (Object, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return Object{}, err
	}

	endpoint := fmt.Sprintf("%s/vault/v1/kv/%s", c.Endpoint, opts.Id)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return Object{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Object{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Object{}, err
	}

	var body Object
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DeleteObject deletes an stored Object.
func (c *Client) DeleteObject(ctx context.Context, opts DeleteObjectOpts) (DeleteObjectResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/vault/v1/kv/%s", c.Endpoint, opts.Id)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return DeleteObjectResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return DeleteObjectResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return DeleteObjectResponse{}, err
	}

	var body DeleteObjectResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// CreateDataKey generates a data key for local encryption.
func (c *Client) CreateDataKey(ctx context.Context, opts CreateDataKeyOpts) (DataKeyPair, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return DataKeyPair{}, err
	}

	endpoint := fmt.Sprintf("%s/vault/v1/keys/data-key", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return DataKeyPair{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return DataKeyPair{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return DataKeyPair{}, err
	}

	var body DataKeyPair
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DecryptDataKey decrypt a data key that was previously encrypted using Vault.
func (c *Client) DecryptDataKey(ctx context.Context, opts DecryptDataKeyOpts) (DataKey, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return DataKey{}, err
	}

	endpoint := fmt.Sprintf("%s/vault/v1/keys/decrypt", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return DataKey{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return DataKey{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return DataKey{}, err
	}

	var body DataKey
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
