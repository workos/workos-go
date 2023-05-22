package pagination

import (
	"context"
	"github.com/workos/workos-go/v2/pkg/directorysync"
)

type Item struct {
	Users directorysync.ListUsersResponse
}

// PaginateList is a method for iterating over the data in the Item struct
func (r Item) PaginateList() ([]directorysync.User, int, error) {
	ctx := context.Background()
	results := make([]directorysync.User, 0)
	totalCount := 0

	// Create a channel to send and receive directorysync.ListUsersResponse
	responseChan := make(chan directorysync.ListUsersResponse)
	errorChan := make(chan error)

	// Start a goroutine to handle pagination
	go func() {
		defer close(responseChan)
		defer close(errorChan)

		// Perform the initial list request
		opts := directorysync.ListUsersOpts{
			Directory: r.Users.Data[0].DirectoryID, // Extract the directory from the first user in the list
		}
		response, err := directorysync.ListUsers(ctx, opts)
		if err != nil {
			errorChan <- err
			return
		}

		// Send the initial response
		responseChan <- response
		totalCount += len(response.Data)

		// Check if there is more data to fetch
		for response.ListMetadata.Before != "" {
			// Make the subsequent list request using the 'Before' parameter
			opts.Before = response.ListMetadata.Before
			response, err = directorysync.ListUsers(ctx, opts)
			if err != nil {
				errorChan <- err
				return
			}

			// Send the response
			responseChan <- response
			totalCount += len(response.Data)
		}
	}()

	// Collect the responses from the channel
	for response := range responseChan {
		results = append(results, response.Data...)
	}

	// Check for any errors
	if err := <-errorChan; err != nil {
		return nil, 0, err
	}

	return results, totalCount, nil
}