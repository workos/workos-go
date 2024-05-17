package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v4/pkg/workos_errors"

	"github.com/workos/workos-go/v4/internal/workos"
	"github.com/workos/workos-go/v4/pkg/common"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

const (
	// Connection Events
	ConnectionActivated   = "connection.activated"
	ConnectionDeactivated = "connection.deactived"
	ConnectionDeleted     = "connection.deleted"
	// Directory Events
	DirectoryActivated = "dsync.activated"
	DirectoryDeleted   = "dsync.deleted"
	// Directory User Events
	DirectoryUserCreated = "dsync.user.created"
	DirectoryUserUpdated = "dsync.user.updated"
	DirectoryUserDeleted = "dsync.user.deleted"
	// Directory Group Events
	DirectoryGroupCreated     = "dsync.group.created"
	DirectoryGroupUpdated     = "dsync.group.updated"
	DirectoryGroupDeleted     = "dsync.group.deleted"
	DirectoryGroupUserAdded   = "dsync.group.user_added"
	DirectroyGroupUserRemoved = "dsync.group.user_removed"
	// User Management Events
	AuthenticationEmailVerificationFailed    = "authentication.email_verification_failed"
	AuthenticationEmailVerificationSucceeded = "authentication.email_verification_succeeded"
	AuthenticationMagicAuthFailed            = "authentication.magic_auth_failed"
	AuthenticationMagicAuthSucceeded         = "authentication.magic_auth_succeeded"
	AuthenticationMfaFailed                  = "authentication.mfa_failed"
	AuthenticationMfaSucceeded               = "authentication.mfa_succeeded"
	AuthenticationOauthFailed                = "authentication.oauth_failed"
	AuthenticationOauthSucceeded             = "authentication.oauth_succeeded"
	AuthenticationPasswordFailed             = "authentication.password_failed"
	AuthenticationPasswordSucceeded          = "authentication.password_succeeded"
	AuthenticationSsoFailed                  = "authentication.sso_failed"
	AuthenticationSsoSucceeded               = "authentication.sso_succeeded"
	UserCreated                              = "user.created"
	UserUpdated                              = "user.updated"
	UserDeleted                              = "user.deleted"
	OrganizationMembershipAdded              = "organization_membership.added" // Deprecated: use OrganizationMembershipCreated instead
	OrganizationMembershipCreated            = "organization_membership.created"
	OrganizationMembershipDeleted            = "organization_membership.deleted"
	OrganizationMembershipUpdated            = "organization_membership.updated"
	OrganizationMembershipRemoved            = "organization_membership.removed" // Deprecated: use OrganizationMembershipDeleted instead
	SessionCreated                           = "session.created"
	InvitationCreated                        = "invitation.created"
	MagicAuthCreated                         = "magic_auth.created"
)

// Client represents a client that performs Event requests to the WorkOS API.
type Client struct {
	// The WorkOS API Key. It can be found in https://dashboard.workos.com/api-keys.
	APIKey string

	// The http.Client that is used to get Event records from WorkOS.
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

// Event contains data about a particular Event.
type Event struct {
	// The Event's unique identifier.
	ID string `json:"id"`

	// The type of Event.
	Event string `json:"event"`

	// The Event's data in raw encoded JSON.
	Data json.RawMessage `json:"data"`

	// The Event's created at date.
	CreatedAt time.Time `json:"created_at"`
}

// ListEventsOpts contains the options to request provisioned Events.
type ListEventsOpts struct {
	// Filter to only return Events of particular types.
	Events []string `url:"events"`

	// Maximum number of records to return.
	Limit int `url:"limit"`

	// Pagination cursor to receive records after a provided Event ID.
	After string `url:"after,omitempty"`

	// Date range start for stream of Events.
	RangeStart string `url:"range_start,omitempty"`

	// Date range end for stream of Events.
	RangeEnd string `url:"range_end,omitempty"`

	OrganizationId string `url:"organization_id,omitempty"`
}

// GetEventsResponse describes the response structure when requesting
// Events.
type ListEventsResponse struct {
	// List of Events.
	Data []Event `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"list_metadata"`
}

// ListEvents gets a list of Events.
func (c *Client) ListEvents(
	ctx context.Context,
	opts ListEventsOpts,
) (ListEventsResponse, error) {
	c.once.Do(c.init)

	endpoint := fmt.Sprintf("%s/events", c.Endpoint)
	req, err := http.NewRequest(
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return ListEventsResponse{}, err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+workos.Version)
	if opts.Limit == 0 {
		opts.Limit = ResponseLimit
	}

	queryValues, err := query.Values(opts)
	if err != nil {
		return ListEventsResponse{}, err
	}

	req.URL.RawQuery = queryValues.Encode()
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return ListEventsResponse{}, err
	}
	defer res.Body.Close()

	if err = workos_errors.TryGetHTTPError(res); err != nil {
		return ListEventsResponse{}, err
	}

	var body ListEventsResponse
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&body)
	return body, err
}
