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
	"github.com/workos-inc/workos-go/pkg/common"
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

// UserEmail contains data about a Directory User's e-mail address.
type UserEmail struct {
	// Flag to indicate if this e-mail is primary.
	Primary bool

	// Directory User's e-mail.
	Value string

	// Type of e-mail (ex. work).
	Type string
}

// UserState represents the active state of a Directory User.
type UserState string

// Constants that enumerate the state of a Directory User.
const (
	Active    UserState = "active"
	Suspended UserState = "suspended"
)

// User contains data about a provisioned Directory User.
type User struct {
	// The User's unique identifier.
	ID string `json:"id"`

	// The User's username.
	Username string `json:"username"`

	// The User's e-mails.
	Emails []UserEmail `json:"emails"`

	// The User's first name.
	FirstName string `json:"first_name"`

	// The User's last name.
	LastName string `json:"last_name"`

	// The User's state.
	State UserState `json:"state"`

	// The User's raw attributes in raw encoded JSON.
	RawAttributes json.RawMessage `json:"raw_attributes"`
}

// ListUsersOpts contains the options to request provisioned Directory Users.
type ListUsersOpts struct {
	// Directory unique identifier.
	Directory string

	// Directory Group unique identifier.
	Group string

	// Maximum number of records to return.
	Limit int

	// Pagination cursor to receive records before a provided Directory ID.
	Before string

	// Pagination cursor to receive records after a provided Directory ID.
	After string
}

// ListUsersResponse describes the response structure when requesting
// provisioned Directory Users.
type ListUsersResponse struct {
	// List of provisioned Users.
	Data []User `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// ListUsers gets a list of provisioned Users for a Directory.
func (c *Client) ListUsers(
	ctx context.Context,
	opts ListUsersOpts,
) (ListUsersResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/directory_users", c.Endpoint)
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
	if opts.Directory != "" {
		q.Add("directory", opts.Directory)
	}
	if opts.Group != "" {
		q.Add("group", opts.Group)
	}
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

// Group contains data about a provisioned Directory Group.
type Group struct {
	// The Group's unique identifier.
	ID string `json:"id"`

	// The Group's name.
	Name string `json:"name"`
}

// ListGroupsOpts contains the options to request provisioned Directory Groups.
type ListGroupsOpts struct {
	// Directory unique identifier.
	Directory string

	// Directory User unique identifier.
	User string

	// Maximum number of records to return.
	Limit int

	// Pagination cursor to receive records before a provided Directory ID.
	Before string

	// Pagination cursor to receive records after a provided Directory ID.
	After string
}

// ListGroupsResponse describes the response structure when requesting
// provisioned Directory Groups.
type ListGroupsResponse struct {
	// List of provisioned Users.
	Data []Group `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// ListGroups gets a list of provisioned Groups for a Directory Endpoint.
func (c *Client) ListGroups(
	ctx context.Context,
	opts ListGroupsOpts,
) (ListGroupsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/directory_groups", c.Endpoint)
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
	if opts.Directory != "" {
		q.Add("directory", opts.Directory)
	}
	if opts.User != "" {
		q.Add("user", opts.User)
	}
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
	// Directory User unique identifier.
	User string
}

// GetUser gets a provisioned User for a Directory Endpoint.
func (c *Client) GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (User, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/directory_users/%s",
		c.Endpoint,
		opts.User,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return User{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return User{}, err
	}

	var body User
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// GetGroupOpts contains the options to request details for a provisioned Directory Group.
type GetGroupOpts struct {
	// Directory Group unique identifier.
	Group string
}

// GetGroup gets a provisioned Group for a Directory.
func (c *Client) GetGroup(
	ctx context.Context,
	opts GetGroupOpts,
) (Group, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf(
		"%s/directory_groups/%s",
		c.Endpoint,
		opts.Group,
	)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return Group{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return Group{}, err
	}
	defer res.Body.Close()

	if err = workos.TryGetHTTPError(res); err != nil {
		return Group{}, err
	}

	var body Group
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}

// DirectoryType represents a Directory type.
type DirectoryType string

// Constants that enumerate the available Directory types.
const (
	OktaSCIMV1_1    DirectoryType = "okta scim v1.1"
	OktaSCIMV2_0    DirectoryType = "okta scim v2.0"
	AzureSCIMV2_0   DirectoryType = "azure scim v2.0"
	GSuiteDirectory DirectoryType = "gsuite directory"
	GenericSCIMV1_1 DirectoryType = "generic scim v1.1"
	GenericSCIMV2_0 DirectoryType = "generic scim v2.0"
)

// DirectoryState represents if a Directory is linked or unlinked.
type DirectoryState string

// Constants that enumerate the linked status of a Directory.
const (
	Linked   DirectoryState = "linked"
	Unlinked DirectoryState = "unlinked"
)

// Directory contains data about a project's directory.
type Directory struct {
	// Directory unique identifier.
	ID string `json:"id"`

	// Directory name.
	Name string `json:"name"`

	// Directory domain.
	Domain string `json:"domain"`

	// Externally used identifier for the Directory.
	ExternalKey string `json:"external_key"`

	// Identifier for the Directory's Environment.
	EnvironmentID string `json:"environment_id"`

	// Type of the directory.
	Type DirectoryType `json:"type"`

	// Linked status for the Directory.
	State DirectoryState `json:"state"`
}

// ListDirectoriesOpts contains the options to request a Project's Directories.
type ListDirectoriesOpts struct {
	// Domain of a Directory. Can be empty.
	Domain string

	// Searchable text for a Directory. Can be empty.
	Search string

	// Maximum number of records to return.
	Limit int

	// Pagination cursor to receive records before a provided Directory ID.
	Before string

	// Pagination cursor to receive records after a provided Directory ID.
	After string
}

// ListDirectoriesResponse describes the response structure when requesting
// existing Directories.
type ListDirectoriesResponse struct {
	// List of Directories.
	Data []Directory `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// ListDirectories gets details of existing Directories.
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
	q.Add("domain", opts.Domain)
	q.Add("search", opts.Search)
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
