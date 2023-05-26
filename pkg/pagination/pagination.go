package pagination

import (
	"context"
	"github.com/workos/workos-go/v2/pkg/directorysync"
)

type Item struct {
	Users directorysync.ListUsersResponse
}


func (r Item) PaginateList() ([]directorysync.User, error) {
	ctx := context.Background()
	results := make([]directorysync.User, 0)

	// Create a channel to send and receive directorysync.ListUsersResponse
	responseChan := make(chan directorysync.ListUsersResponse)
	errorChan := make(chan error)

	// Start a goroutine to handle pagination
	go func() {
		defer close(responseChan)
		defer close(errorChan)

		
		// Perform the initial list request
		opts := directorysync.ListUsersOpts{
			Order: r.Users.PaginationParams.Order,
			Limit: r.Users.PaginationParams.Limit,
		}
		
		// Send the initial response
		responseChan <- r.Users
		// Check if there is more data to fetch
		for r.Users.ListMetadata.Before != "" {
			// Make the subsequent list request using the 'Before' parameter
			opts.Before = r.Users.ListMetadata.Before
			response, err := directorysync.ListUsers(ctx, opts)
			if err != nil {
				errorChan <- err
				return
			}

			// Send the response
			responseChan <- response
		}
	}()

	// Collect the responses from the channel
	for response := range responseChan {
		results = append(results, response.Data...)
	}

	// Check for any errors
	if err := <-errorChan; err != nil {
		return nil, err
	}

	return results,  nil
}