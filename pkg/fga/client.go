package fga

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

const (
	SchemaConvertEndpoint = "%s/fga/v1/schemas/convert"
)

// Order represents the order of records.
type Order string

// Constants that enumerate the available orders.
const (
	Asc                      Order = "asc"
	Desc                     Order = "desc"
	CheckOpAllOf                   = "all_of"
	CheckOpAnyOf                   = "any_of"
	CheckOpBatch                   = "batch"
	CheckResultAuthorized          = "authorized"
	CheckResultNotAuthorized       = "not_authorized"
	WarrantOpCreate                = "create"
	WarrantOpDelete                = "delete"
)

// Client represents a client that performs FGA requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to get FGA records from WorkOS.
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

// Resources
type Resource struct {
	// The type of the resource.
	ResourceType string `json:"resource_type"`

	// The customer defined string identifier for this resource.
	ResourceId string `json:"resource_id"`

	// Map containing additional information about this resource.
	Meta map[string]interface{} `json:"meta"`
}

type GetResourceOpts struct {
	// The type of the resource.
	ResourceType string

	// The customer defined string identifier for this resource.
	ResourceId string
}

type ListResourcesOpts struct {
	// The type of the resource.
	ResourceType string `url:"resource_type,omitempty"`

	// Searchable text for a Resource. Can be empty.
	Search string `url:"search,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided Resource ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided Resource ID.
	After string `url:"after,omitempty"`
}

// ListResourcesResponse describes the response structure when requesting Resources
type ListResourcesResponse struct {
	// List of provisioned Resources.
	Data []Resource `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type CreateResourceOpts struct {
	// The type of the resource.
	ResourceType string `json:"resource_type"`

	// The customer defined string identifier for this resource.
	ResourceId string `json:"resource_id,omitempty"`

	// Map containing additional information about this resource.
	Meta map[string]interface{} `json:"meta,omitempty"`
}

type UpdateResourceOpts struct {
	// The type of the resource.
	ResourceType string `json:"resource_type"`

	// The customer defined string identifier for this resource.
	ResourceId string `json:"resource_id"`

	// Map containing additional information about this resource.
	Meta map[string]interface{} `json:"meta,omitempty"`
}

// DeleteResourceOpts contains the options to delete a resource.
type DeleteResourceOpts struct {
	// The type of the resource.
	ResourceType string

	// The customer defined string identifier for this resource.
	ResourceId string
}

// Resource types
type ResourceType struct {
	// Unique string ID of the resource type.
	Type string `json:"type"`

	// Set of relationships that subjects can have on resources of this type.
	Relations map[string]interface{} `json:"relations"`
}

type ListResourceTypesOpts struct {
	// Maximum number of records to return.
	Limit int `url:"limit,omitempty"`

	// The order in which to paginate records.
	Order Order `url:"order,omitempty"`

	// Pagination cursor to receive records before a provided ResourceType ID.
	Before string `url:"before,omitempty"`

	// Pagination cursor to receive records after a provided ResourceType ID.
	After string `url:"after,omitempty"`
}

type ListResourceTypesResponse struct {
	// List of Resource Types.
	Data []ResourceType `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

type UpdateResourceTypeOpts struct {
	// Unique string ID of the resource type.
	Type string `json:"type"`

	// Set of relationships that subjects can have on resources of this type.
	Relations map[string]interface{} `json:"relations"`
}

// Warrants
type Subject struct {
	// The type of the subject.
	ResourceType string `json:"resource_type"`

	// The customer defined string identifier for this subject.
	ResourceId string `json:"resource_id"`

	// The relation of the subject.
	Relation string `json:"relation,omitempty"`
}

type Warrant struct {
	// Type of resource to assign a relation to. Must be an existing type.
	ResourceType string `json:"resource_type"`

	// Id of the resource to assign a relation to.
	ResourceId string `json:"resource_id"`

	// Relation to assign to the resource.
	Relation string `json:"relation"`

	// Subject of the warrant
	Subject Subject `json:"subject"`

	// Policy that must evaluate to true for warrant to be valid
	Policy string `json:"policy,omitempty"`
}

type ListWarrantsOpts struct {
	// Only return warrants whose resourceType matches this value.
	ResourceType string `url:"resource_type,omitempty"`

	// Only return warrants whose resourceId matches this value.
	ResourceId string `url:"resource_id,omitempty"`

	// Only return warrants whose relation matches this value.
	Relation string `url:"relation,omitempty"`

	// Only return warrants with a subject whose resourceType matches this value.
	SubjectType string `url:"subject_type,omitempty"`

	// Only return warrants with a subject whose resourceId matches this value.
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

	// Type of resource to assign a relation to. Must be an existing type.
	ResourceType string `json:"resource_type"`

	// Id of the resource to assign a relation to.
	ResourceId string `json:"resource_id"`

	// Relation to assign to the resource.
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

func (context Context) EncodeValues(key string, values *url.Values) error {
	jsonCtx, err := json.Marshal(context)
	if err != nil {
		return err
	}
	values.Set(key, string(jsonCtx))
	return nil
}

type WarrantCheck struct {
	// The type of the resource.
	ResourceType string `json:"resource_type"`

	// Id of the specific resource.
	ResourceId string `json:"resource_id"`

	// Relation to check between the resource and subject.
	Relation string `json:"relation"`

	// The subject that must have the specified relation.
	Subject Subject `json:"subject"`

	// Contextual data to use for the access check.
	Context Context `json:"context,omitempty"`
}

type CheckOpts struct {
	// The operator to use for the given warrants.
	Op string `json:"op,omitempty"`

	// List of warrants to check.
	Checks []WarrantCheck `json:"checks"`

	// Flag to include debug information in the response.
	Debug bool `json:"debug,omitempty"`

	// Optional token to specify desired read consistency
	WarrantToken string `json:"-"`
}

type CheckBatchOpts struct {
	// List of warrants to check.
	Checks []WarrantCheck `json:"checks"`

	// Flag to include debug information in the response.
	Debug bool `json:"debug,omitempty"`

	// Optional token to specify desired read consistency
	WarrantToken string `json:"-"`
}

type CheckResponse struct {
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
	// The type of the resource.
	ResourceType string `json:"resource_type"`

	// Id of the specific resource.
	ResourceId string `json:"resource_id"`

	// Relation between the resource and subject.
	Relation string `json:"relation"`

	// Warrant matching the provided query
	Warrant Warrant `json:"warrant"`

	// Specifies whether the warrant is implicitly defined.
	IsImplicit bool `json:"is_implicit"`

	// Metadata of the resource.
	Meta map[string]interface{} `json:"meta,omitempty"`
}

type QueryResponse struct {
	// List of query results.
	Data []QueryResult `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

// Schema
type ConvertSchemaToResourceTypesOpts struct {
	// The schema to convert to resource types.
	Schema string
}

type ConvertSchemaWarning struct {
	// The warning message.
	Message string `json:"message"`
}

type ConvertResourceTypesToSchemaOpts struct {
	// The version of the transpiler to use.
	Version string `json:"version"`

	// The resource types to convert to a schema.
	ResourceTypes []ResourceType `json:"resource_types"`
}

type ConvertSchemaResponse struct {
	// The version transpiler used to convert the schema.
	Version string `json:"version"`

	// Warnings generated from schema issues.
	Warnings []ConvertSchemaWarning `json:"warnings,omitempty"`

	// The schema generated from the resource types.
	Schema *string `json:"schema,omitempty"`

	// The resource types generated from the schema.
	ResourceTypes []ResourceType `json:"resource_types,omitempty"`
}

// GetResource gets a Resource.
func (c *Client) GetResource(ctx context.Context, opts GetResourceOpts) (Resource, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/resources/%s/%s", c.Endpoint, opts.ResourceType, opts.ResourceId)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Resource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Resource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Resource{}, err
	}

	var body Resource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListResources gets a list of FGA resources.
func (c *Client) ListResources(ctx context.Context, opts ListResourcesOpts) (ListResourcesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/resources", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListResourcesResponse{}, err
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
		return ListResourcesResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListResourcesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListResourcesResponse{}, err
	}

	var body ListResourcesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// CreateResource creates a new resource
func (c *Client) CreateResource(ctx context.Context, opts CreateResourceOpts) (Resource, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return Resource{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/resources", c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return Resource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Resource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Resource{}, err
	}

	var body Resource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// UpdateResource updates an existing Resource
func (c *Client) UpdateResource(ctx context.Context, opts UpdateResourceOpts) (Resource, error) {
	c.once.Do(c.init)

	// UpdateResourceChangeOpts contains the options to update a Resource minus the ResourceType and ResourceId
	type UpdateResourceChangeOpts struct {
		Meta map[string]interface{} `json:"meta"`
	}

	update_opts := UpdateResourceChangeOpts{Meta: opts.Meta}

	data, err := c.JSONEncode(update_opts)
	if err != nil {
		return Resource{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/resources/%s/%s", c.Endpoint, opts.ResourceType, opts.ResourceId)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return Resource{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Resource{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return Resource{}, err
	}

	var body Resource
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err

}

// DeleteResource deletes a Resource
func (c *Client) DeleteResource(ctx context.Context, opts DeleteResourceOpts) error {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/resources/%s/%s", c.Endpoint, opts.ResourceType, opts.ResourceId)
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

// ListResourceTypes gets a list of FGA resource types.
func (c *Client) ListResourceTypes(ctx context.Context, opts ListResourceTypesOpts) (ListResourceTypesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/fga/v1/resource-types", c.Endpoint)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return ListResourceTypesResponse{}, err
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
		return ListResourceTypesResponse{}, err
	}

	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListResourceTypesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListResourceTypesResponse{}, err
	}

	var body ListResourceTypesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// BatchUpdateResourceTypes sets the environment's set of resource types to match the resource types passed.
func (c *Client) BatchUpdateResourceTypes(ctx context.Context, opts []UpdateResourceTypeOpts) ([]ResourceType, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return []ResourceType{}, err
	}

	endpoint := fmt.Sprintf("%s/fga/v1/resource-types", c.Endpoint)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return []ResourceType{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return []ResourceType{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return []ResourceType{}, err
	}

	var body []ResourceType
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

func (c *Client) CheckBatch(ctx context.Context, opts CheckBatchOpts) ([]CheckResponse, error) {
	c.once.Do(c.init)

	checkOpts := CheckOpts{
		Op:           CheckOpBatch,
		Checks:       opts.Checks,
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

	q, err := query.Values(opts)
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

// ConvertSchemaToResourceTypes converts a schema to resource types.
func (c *Client) ConvertSchemaToResourceTypes(ctx context.Context, opts ConvertSchemaToResourceTypesOpts) (ConvertSchemaResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(SchemaConvertEndpoint, c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(opts.Schema))
	if err != nil {
		return ConvertSchemaResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ConvertSchemaResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ConvertSchemaResponse{}, err
	}

	var body ConvertSchemaResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ConvertResourceTypesToSchema converts resource types to a schema.
func (c *Client) ConvertResourceTypesToSchema(ctx context.Context, opts ConvertResourceTypesToSchemaOpts) (ConvertSchemaResponse, error) {
	c.once.Do(c.init)

	data, err := c.JSONEncode(opts)
	if err != nil {
		return ConvertSchemaResponse{}, err
	}

	endpoint := fmt.Sprintf(SchemaConvertEndpoint, c.Endpoint)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return ConvertSchemaResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ConvertSchemaResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ConvertSchemaResponse{}, err
	}

	var body ConvertSchemaResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
