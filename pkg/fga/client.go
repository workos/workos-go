package fga

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
	"github.com/workos/workos-go/v4/pkg/workos_errors"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Order represents the order of records.
type Order string

// Constants that enumerate the available orders.
const (
	CheckResultAuthorized       = "Authorized"
	Asc                   Order = "asc"
	Desc                  Order = "desc"
)

// Client represents a client that performs FGA requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to get FGA records from WorkOS.
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	// The function used to encode in JSON. Defaults to json.Marshal.
	JSONEncode func(v interface{}) ([]byte, error)

	once sync.Once
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}

	if c.JSONEncode == nil {
		c.JSONEncode = json.Marshal
	}
}

// Objects
type Object struct {
	// The type of the object.
	ObjectType string `json:"object_type"`

	// The customer defined string identifier for this object.
	ObjectId string `json:"object_id"`

	// Map containing additional information about this object.
	Meta map[string]interface{} `json:"meta"`
}

type GetObjectOpts struct {
	// The type of the object.
	ObjectType string

	// The customer defined string identifier for this object.
	ObjectId string
}

type ListObjectsOpts struct {
	// The type of the object.
	ObjectType string `url:"object_type,omitempty"`

	// Searchable text for an Object. Can be empty.
	Search string `url:"search,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Object ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Object ID.
	After string `url:"after,omitempty"`
}

// ListObjectsResponse describes the response structure when requesting Objects
type ListObjectsResponse struct {
	// List of provisioned Objects.
	Data []Object `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type CreateObjectOpts struct {
	// The type of the object.
	ObjectType string `json:"object_type"`

	// The customer defined string identifier for this object.
	ObjectId string `json:"object_id,omitempty"`

	// Map containing additional information about this object.
	Meta map[string]interface{} `json:"meta,omitempty"`
}

type UpdateObjectOpts struct {
	// The type of the object.
	ObjectType string `json:"object_type"`

	// The customer defined string identifier for this object.
	ObjectId string `json:"object_id"`

	// Map containing additional information about this object.
	Meta map[string]interface{} `json:"meta,omitempty"`
}

// DeleteObjectOpts contains the options to delete an object.
type DeleteObjectOpts struct {
	// The type of the object.
	ObjectType string

	// The customer defined string identifier for this object.
	ObjectId string
}

// Object types
type ObjectType struct {
	// Unique string ID of the object type.
	Type string `json:"type"`

	// Set of relationships that subjects can have on objects of this type.
	Relations map[string]interface{} `json:"relations"`
}

type ListObjectTypesOpts struct {
	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided ObjectType ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided ObjectType ID.
	After string `url:"after,omitempty"`
}

type ListObjectTypesResponse struct {
	// List of Object Types.
	Data []ObjectType `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type UpdateObjectTypeOpts struct {
	// Unique string ID of the object type.
	Type string `json:"type"`

	// Set of relationships that subjects can have on objects of this type.
	Relations map[string]interface{} `json:"relations"`
}

// Warrants
type Subject struct {
	// The type of the subject.
	ObjectType string `json:"object_type"`

	// The customer defined string identifier for this subject.
	ObjectId string `json:"object_id"`

	// The relation of the subject.
	Relation string `json:"relation,omitempty"`
}

type Warrant struct {
	// Type of object to assign a relation to. Must be an existing type.
	ObjectType string `json:"object_type"`

	// Id of the object to assign a relation to.
	ObjectId string `json:"object_id"`

	// Relation to assign to the object.
	Relation string `json:"relation"`

	// Subject of the warrant
	Subject Subject `json:"subject"`

	// Policy that must evaluate to true for warrant to be valid
	Policy string `json:"policy,omitempty"`
}

type ListWarrantsOpts struct {
	// Only return warrants whose objectType matches this value.
	ObjectType string `url:"object_type,omitempty"`

	// Only return warrants whose objectId matches this value.
	ObjectId string `url:"object_id,omitempty"`

	// Only return warrants whose relation matches this value.
	Relation string `url:"relation,omitempty"`

	// Only return warrants with a subject whose objectType matches this value.
	SubjectType string `url:"subject_type,omitempty"`

	// Only return warrants with a subject whose objectId matches this value.
	SubjectId string `url:"subject_id,omitempty"`

	// Only return warrants with a subject whose relation matches this value.
	SubjectRelation string `url:"subject_relation,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// Pagination cursor to receive records after a provided Warrant ID.
	After string `url:"after,omitempty"`

	// Optional token to specify desired read consistency
	WarrantToken string `url:"-"`
}

// ListWarrantsResponse describes the response structure when requesting Warrants
type ListWarrantsResponse struct {
	// List of provisioned Warrants.
	Data []Warrant `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type WriteWarrantOpts struct {
	// Operation to perform for the given warrant
	Op string `json:"op,omitempty"`

	// Type of object to assign a relation to. Must be an existing type.
	ObjectType string `json:"object_type"`

	// Id of the object to assign a relation to.
	ObjectId string `json:"object_id"`

	// Relation to assign to the object.
	Relation string `json:"relation"`

	// Subject of the warrant
	Subject Subject `json:"subject"`

	// Policy that must evaluate to true for warrant to be valid
	Policy string `json:"policy,omitempty"`
}

type WriteWarrantResponse struct {
	WarrantToken string `json:"warrant_token"`
}

// Check
type Context map[string]interface{}

type WarrantCheck struct {
	// The type of the object.
	ObjectType string `json:"object_type"`

	// Id of the specific object.
	ObjectId string `json:"object_id"`

	// Relation to check between the object and subject.
	Relation string `json:"relation"`

	// The subject that must have the specified relation.
	Subject Subject `json:"subject"`

	// Contextual data to use for the access check.
	Context Context `json:"context,omitempty"`
}

type CheckOpts struct {
	// Warrant to check
	Warrant WarrantCheck `json:"warrant_check"`

	// Flag to include debug information in the response.
	Debug bool `json:"debug,omitempty"`

	// Optional token to specify desired read consistency
	WarrantToken string `json:"-"`
}

type CheckManyOpts struct {
	// The operator to use for the given warrants.
	Op string `json:"op,omitempty"`

	// List of warrants to check.
	Checks []WarrantCheck `json:"checks"`

	// Flag to include debug information in the response.
	Debug bool `json:"debug,omitempty"`

	// Optional token to specify desired read consistency
	WarrantToken string `json:"-"`
}

type BatchCheckOpts struct {
	// List of warrants to check.
	Warrants []WarrantCheck `json:"warrants"`

	// Flag to include debug information in the response.
	Debug bool `json:"debug,omitempty"`

	// Optional token to specify desired read consistency
	WarrantToken string `json:"-"`
}

type CheckResponse struct {
	Code       int64     `json:"code"`
	Result     string    `json:"result"`
	IsImplicit bool      `json:"is_implicit"`
	DebugInfo  DebugInfo `json:"debug_info,omitempty"`
}

func (checkResponse CheckResponse) Authorized() bool {
	return checkResponse.Result == CheckResultAuthorized
}

type DebugInfo struct {
	ProcessingTime time.Duration     `json:"processing_time"`
	DecisionTree   *DecisionTreeNode `json:"decision_tree"`
}

type DecisionTreeNode struct {
	Check          WarrantCheck       `json:"check"`
	Policy         string             `json:"policy,omitempty"`
	Decision       string             `json:"decision"`
	ProcessingTime time.Duration      `json:"processing_time"`
	Children       []DecisionTreeNode `json:"children"`
}

// Query
type QueryOpts struct {
	// Query to be executed.
	Query string `url:"q"`

	// Contextual data to use for the query.
	Context Context `url:"context,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Warrant ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Warrant ID.
	After string `url:"after,omitempty"`

	// Optional token to specify desired read consistency
	WarrantToken string `url:"-"`
}

type QueryResult struct {
	// The type of the object.
	ObjectType string `json:"object_type"`

	// Id of the specific object.
	ObjectId string `json:"object_id"`

	// Relation between the object and subject.
	Relation string `json:"relation"`

	// Warrant matching the provided query
	Warrant Warrant `json:"warrant"`

	// Specifies whether the warrant is implicitly defined.
	IsImplicit bool `json:"is_implicit"`

	// Metadata of the object.
	Meta map[string]interface{} `json:"meta,omitempty"`
}

type QueryResponse struct {
	// List of query results.
	Data []QueryResult `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

// GetObject gets an Object.
func (c *Client) GetObject(ctx context.Context, opts GetObjectOpts) (Object, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/objects/%s/%s", c.Endpoint, opts.ObjectType, opts.ObjectId)
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

// ListObjects gets a list of FGA objects.
func (c *Client) ListObjects(ctx context.Context, opts ListObjectsOpts) (ListObjectsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/objects", c.Endpoint)
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

// CreateObject creates a new object
func (c *Client) CreateObject(ctx context.Context, opts CreateObjectOpts) (Object, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return Object{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/objects", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
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

// UpdateObject updates an existing Object
func (c *Client) UpdateObject(ctx context.Context, opts UpdateObjectOpts) (Object, error) {
	c.once.Do(c.init)

	// UpdateObjectChangeOpts contains the options to update an Object minus the ObjectType and ObjectId
	type UpdateObjectChangeOpts struct {
		Meta map[string]interface{} `json:"meta"`
	}

	update_opts := UpdateObjectChangeOpts{Meta: opts.Meta}

	data, err := c.JSONEncode(update_opts)
	if err != nil {
		return Object{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/objects/%s/%s", c.Endpoint, opts.ObjectType, opts.ObjectId)
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

// DeleteObject deletes an Object
func (c *Client) DeleteObject(ctx context.Context, opts DeleteObjectOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/objects/%s/%s", c.Endpoint, opts.ObjectType, opts.ObjectId)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return workos_errors.TryGetHTTPError(res)
}

// ListObjectTypes gets a list of FGA object types.
func (c *Client) ListObjectTypes(ctx context.Context, opts ListObjectTypesOpts) (ListObjectTypesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/object-types", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListObjectTypesResponse{}, err
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
		return ListObjectTypesResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListObjectTypesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListObjectTypesResponse{}, err
	}

	var body ListObjectTypesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// BatchUpdateObjectTypes sets the environment's set of object types to match the object types passed.
func (c *Client) BatchUpdateObjectTypes(ctx context.Context, opts []UpdateObjectTypeOpts) ([]ObjectType, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return []ObjectType{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/object-types", c.Endpoint)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return []ObjectType{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return []ObjectType{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return []ObjectType{}, err
	}

	var body []ObjectType
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListWarrants gets a list of Warrants.
func (c *Client) ListWarrants(ctx context.Context, opts ListWarrantsOpts) (ListWarrantsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/warrants", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListWarrantsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	if opts.WarrantToken != "" {
		req.Header.Set("Warrant-Token", opts.WarrantToken)
	}

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	q, err := query.Values(opts)
	if err != nil {
		return ListWarrantsResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListWarrantsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListWarrantsResponse{}, err
	}

	var body ListWarrantsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// WriteWarrant performs a write operation on a Warrant.
func (c *Client) WriteWarrant(ctx context.Context, opts WriteWarrantOpts) (WriteWarrantResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return WriteWarrantResponse{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/warrants", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return WriteWarrantResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return WriteWarrantResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return WriteWarrantResponse{}, err
	}

	var body WriteWarrantResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// BatchWriteWarrants performs a write operation on a Warrant.
func (c *Client) BatchWriteWarrants(ctx context.Context, opts []WriteWarrantOpts) (WriteWarrantResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return WriteWarrantResponse{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/warrants", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return WriteWarrantResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return WriteWarrantResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return WriteWarrantResponse{}, err
	}

	var body WriteWarrantResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

func (c *Client) Check(ctx context.Context, opts CheckOpts) (CheckResponse, error) {
	return c.CheckMany(ctx, CheckManyOpts{
		Checks:       []WarrantCheck{opts.Warrant},
		Debug:        opts.Debug,
		WarrantToken: opts.WarrantToken,
	})
}

func (c *Client) CheckMany(ctx context.Context, opts CheckManyOpts) (CheckResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return CheckResponse{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/check", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return CheckResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	if opts.WarrantToken != "" {
		req.Header.Set("Warrant-Token", opts.WarrantToken)
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return CheckResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return CheckResponse{}, err
	}

	var checkResponse CheckResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&checkResponse)
	if err != nil {
		return CheckResponse{}, err
	}

	return checkResponse, nil
}

func (c *Client) BatchCheck(ctx context.Context, opts BatchCheckOpts) ([]CheckResponse, error) {
	c.once.Do(c.init)

	checkOpts := CheckManyOpts{
		Op:           "batch",
		Checks:       opts.Warrants,
		Debug:        opts.Debug,
		WarrantToken: opts.WarrantToken,
	}
	data, err := c.JSONEncode(checkOpts)
	if err != nil {
		return []CheckResponse{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/check", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return []CheckResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	if opts.WarrantToken != "" {
		req.Header.Set("Warrant-Token", opts.WarrantToken)
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return []CheckResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return []CheckResponse{}, err
	}

	var checkResponses []CheckResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&checkResponses)
	if err != nil {
		return []CheckResponse{}, err
	}

	return checkResponses, nil
}

// Query executes a query for a set of resources.
func (c *Client) Query(ctx context.Context, opts QueryOpts) (QueryResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/query", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return QueryResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	if opts.WarrantToken != "" {
		req.Header.Set("Warrant-Token", opts.WarrantToken)
	}

	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	if opts.Order == "" {
		opts.Order = Desc
	}

	type QueryUrlOpts struct {
		Query        string `url:"q"`
		Context      string `url:"context,omitempty"`
		Limit        int    `url:"limit,omitempty"`
		Order        Order  `url:"order,omitempty"`
		Before       string `url:"before,omitempty"`
		After        string `url:"after,omitempty"`
		WarrantToken string `url:"-"`
	}

	var jsonCtx []byte
	if opts.Context != nil {
		jsonCtx, err = json.Marshal(opts.Context)
		if err != nil {
			return QueryResponse{}, err
		}
	}
	queryUrlOpts := QueryUrlOpts{
		Query:   opts.Query,
		Context: string(jsonCtx),
		Limit:   opts.Limit,
		Order:   opts.Order,
		Before:  opts.Before,
		After:   opts.After,
	}

	q, err := query.Values(queryUrlOpts)
	if err != nil {
		return QueryResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return QueryResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return QueryResponse{}, err
	}

	var body QueryResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
