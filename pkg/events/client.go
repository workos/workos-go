
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/workos/workos-go/v2/pkg/workos_errors"

	"github.com/workos/workos-go/v2/internal/workos"
	"github.com/workos/workos-go/v2/pkg/common"
)

// ResponseLimit is the default number of records to limit a response to.
const ResponseLimit = 10

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
	CreatedAt string `json:"created_at"`
}

// ListeEventsOpts contains the options to request provisioned Events.
type ListeEventsOpts struct {
	// Filter to only return Events of particular types.
	Events string[] `url:"events,omitempty"`

	// Maximum number of records to return.
	Limit int `url:"limit"`

	// Pagination cursor to receive records after a provided Event ID.
	After string `url:"after,omitempty"`

	// Date range start for stream of Events.
	RangeStart string `url:"after,omitempty"`

	// Date range end for stream of Events.
	RangeEnd string `url:"after,omitempty"`
}

// ListEventsResponse describes the response structure when requesting
// Events.
type ListEventsResponse struct {
	// List of Events.
	Data []Event `json:"data"`

	// Cursor pagination options.
	ListMetadata common.ListMetadata `json:"listMetadata"`
}

// ListEvents gets a list of Events.
func (c *Client) ListEvents(
	ctx context.Context,
	opts ListeEventsOpts,
) (ListeEventsOpts, error) {
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

	v, err := query.Values(opts)
	if err != nil {
		return ListEventsResponse{}, err
	}

	req.URL.RawQuery = v.Encode()
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

