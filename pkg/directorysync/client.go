package directorysync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/workos-inc/workos-go/internal/workos"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

// Client represents a client that performs Directory Sync requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to get Directory Sync records from WorkOS.
	// Defaults to http.Client.
	HTTPClient *http.Client

	// The endpoint to WorkOS API. Defaults to https://api.workos.com.
	Endpoint string

	once sync.Once
}

func (c *Client) init() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if c.Endpoint == "" {
		c.Endpoint = "https://api.workos.com"
	}
}

// DirectoryUserEmail contains data about a Directory User's e-mail address.
type DirectoryUserEmail struct {
	// Flag to indicate if this e-mail is primary.
	Primary bool

	// Directory User's e-mail.
	Value string

	// Type of e-mail (ex. work).
	Type string
}

// DirectoryUser contains data about a provisioned Directory User.
type DirectoryUser struct {
	// The User's unique identifier.
	ID string `json:"id"`

	// The User's username.
	Username string `json:"username"`

	// The User's e-mails.
	Emails []DirectoryUserEmail `json:"emails"`

	// The User's first name.
	FirstName string `json:"first_name"`

	// The User's last name.
	LastName string `json:"last_name"`

	// The User's raw attributes in raw encoded JSON.
	RawAttributes json.RawMessage `json:"raw_attributes"`
}

// ListMetadata contains pagination options for Directory records.
type ListMetadata struct {
	// Pagination cursor to receive records before a provided ID.
	Before string `json:"before"`

	// Pagination cursor to receive records before a provided ID.
	After string `json:"after"`
}

// ListUsersOpts contains the options to request provisioned Directory Users.
type ListUsersOpts struct {
	// Directory Endpoint unique identifier.
	DirectoryEndpointID string

	// Maximum number of records to return.
	Limit int

	// Pagination cursor to receive records before a provided Directory Endpoint ID.
	Before string

	// Pagination cursor to receive records after a provided Directory Endpoint ID.
	After string
}

// ListUsersResponse describes the response structure when requesting
// provisioned Directory Users.
type ListUsersResponse struct {
	// List of provisioned Users.
	Data []DirectoryUser `json:"data"`

	// Cursor pagination options.
	ListMetadata ListMetadata `json:"listMetadata"`
}

// ListUsers gets a list of provisioned Users for a Directory Endpoint.
func (c *Client) ListUsers(
	ctx context.Context,
	opts ListUsersOpts,
) (ListUsersResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/directories/%s/users", c.Endpoint, opts.DirectoryEndpointID)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListUsersResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	limit := ResponseLimit
	if opts.Limit != 0 {
		limit = opts.Limit
	}
	q := req.URL.Query()
	q.Add("before", opts.Before)
	q.Add("after", opts.After)
	q.Add("limit", strconv.Itoa(limit))
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListUsersResponse{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return ListUsersResponse{}, err
	}

	var body ListUsersResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DirectoryGroup contains data about a provisioned Directory Group.
type DirectoryGroup struct {
	// The Group's unique identifier.
	ID string `json:"id"`

	// The Group's name.
	Name string `json:"name"`
}

// ListGroupsOpts contains the options to request provisioned Directory Groups.
type ListGroupsOpts struct {
	// Directory Endpoint unique identifier.
	DirectoryEndpointID string

	// Maximum number of records to return.
	Limit int

	// Pagination cursor to receive records before a provided Directory Endpoint ID.
	Before string

	// Pagination cursor to receive records after a provided Directory Endpoint ID.
	After string
}

// ListGroupsResponse describes the response structure when requesting
// provisioned Directory Groups.
type ListGroupsResponse struct {
	// List of provisioned Users.
	Data []DirectoryGroup `json:"data"`

	// Cursor pagination options.
	ListMetadata ListMetadata `json:"listMetadata"`
}

// ListGroups gets a list of provisioned Groups for a Directory Endpoint.
func (c *Client) ListGroups(
	ctx context.Context,
	opts ListGroupsOpts,
) (ListGroupsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/directories/%s/groups", c.Endpoint, opts.DirectoryEndpointID)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListGroupsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	limit := ResponseLimit
	if opts.Limit != 0 {
		limit = opts.Limit
	}
	q := req.URL.Query()
	q.Add("before", opts.Before)
	q.Add("after", opts.After)
	q.Add("limit", strconv.Itoa(limit))
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListGroupsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return ListGroupsResponse{}, err
	}

	var body ListGroupsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetUserOpts contains the options to request details for a provisioned Directory User.
type GetUserOpts struct {
	// Directory Endpoint unique identifier.
	DirectoryEndpointID string

	// Directory User unique identifier.
	DirectoryUserID string
}

// GetUser gets a provisioned User for a Directory Endpoint.
func (c *Client) GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (DirectoryUser, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/directories/%s/users/%s",
		c.Endpoint,
		opts.DirectoryEndpointID,
		opts.DirectoryUserID,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return DirectoryUser{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return DirectoryUser{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return DirectoryUser{}, err
	}

	var body DirectoryUser
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// ListUserGroupsOpts contains the options to request details for a
// provisioned Directory User's Groups.
type ListUserGroupsOpts struct {
	// Directory Endpoint unique identifier.
	DirectoryEndpointID string

	// Directory User unique identifier.
	DirectoryUserID string
}

// ListUserGroups gets details of a provisioned User's Groups for a Directory Endpoint.
func (c *Client) ListUserGroups(
	ctx context.Context,
	opts ListUserGroupsOpts,
) ([]DirectoryGroup, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/directories/%s/users/%s/groups",
		c.Endpoint,
		opts.DirectoryEndpointID,
		opts.DirectoryUserID,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return []DirectoryGroup{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return []DirectoryGroup{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return []DirectoryGroup{}, err
	}

	var body []DirectoryGroup
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DirectoryEndpointType represents a Directory type.
type DirectoryEndpointType string

// Constants that enumerate the available Directory types.
const (
	OktaSCIMV1_1    DirectoryEndpointType = "okta scim v1.1"
	OktaSCIMV2_0    DirectoryEndpointType = "okta scim v2.0"
	AzureSCIMV2_0   DirectoryEndpointType = "azure scim v2.0"
	GSuiteDirectory DirectoryEndpointType = "gsuite directory"
	GenericSCIMV1_1 DirectoryEndpointType = "generic scim v1.1"
	GenericSCIMV2_0 DirectoryEndpointType = "generic scim v2.0"
)

// DirectoryEndpointState represents if a Directory is linked or unlinked.
type DirectoryEndpointState string

// Constants that enumerate the linked status of a Directory.
const (
	Linked   DirectoryEndpointState = "linked"
	Unlinked DirectoryEndpointState = "unlinked"
)

// DirectoryEndpoint contains data about a project's directory.
type DirectoryEndpoint struct {
	// Directory Endpoint unique identifier.
	ID string `json:"id"`

	// Directory Endpoint name.
	Name string `json:"name"`

	// Directory Endpoint domain.
	Domain string `json:"domain"`

	// Externally used identifier for the Directory Endpoint.
	ExternalKey string `json:"external_key"`

	// Bearer Token used to authenticate requests.
	BearerToken string `json:"bearer_token"`

	// Identifier for the Directory Endpoint's Project.
	ProjectID string `json:"project_id"`

	// Directory Type for an Endpoint.
	Type DirectoryEndpointType `json:"type"`

	// Linked status for the Directory Endpoint.
	State DirectoryEndpointState `json:"state"`
}

// ListDirectoriesOpts contains the options to request a project's Directories.
type ListDirectoriesOpts struct {
	// Domain of a Directory Endpoint. Can be empty.
	Domain string

	// Searchable text for a Directory Endpoint. Can be empty.
	Search string

	// Maximum number of records to return.
	Limit int

	// Pagination cursor to receive records before a provided Directory Endpoint ID.
	Before string

	// Pagination cursor to receive records after a provided Directory Endpoint ID.
	After string
}

// ListDirectoriesResponse describes the response structure when requesting
// existing directories.
type ListDirectoriesResponse struct {
	// List of directory endpoints.
	Data []DirectoryEndpoint `json:"data"`

	// Cursor pagination options.
	ListMetadata ListMetadata `json:"listMetadata"`
}

// ListDirectories gets details of existing directories.
func (c *Client) ListDirectories(
	ctx context.Context,
	opts ListDirectoriesOpts,
) (ListDirectoriesResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/directories", c.Endpoint)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListDirectoriesResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	limit := ResponseLimit
	if opts.Limit != 0 {
		limit = opts.Limit
	}
	q := req.URL.Query()
	q.Add("before", opts.Before)
	q.Add("after", opts.After)
	q.Add("limit", strconv.Itoa(limit))
	req.URL.RawQuery = q.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListDirectoriesResponse{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return ListDirectoriesResponse{}, err
	}

	var body ListDirectoriesResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
