// Package directorysync is a package to fetch Directory information from
// WorkOS.
//
// You first need to setup a Directory Endpoint on
// https://dashboard.workos.com/directory-sync.
//
// Example:
//	func main() {
//		directorysync.SetAPIKey("my_api_key")
//
//		directoryUsers, err := directorysync.ListUsers(
//			context.Background(),
//			directorysync.ListUsersOpts{
//				DirectoryEndpointID: "directory_edp_id",
//			},
//		)
//	}
package directorysync

import (
	"context"
)

// DefaultClient is the client used by SetAPIKey and Directory Sync functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Directory Sync requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// ListUsers gets a list of provisioned Users for a Directory Endpoint.
func ListUsers(
	ctx context.Context,
	opts ListUsersOpts,
) (ListUsersResponse, error) {
	return DefaultClient.ListUsers(ctx, opts)
}

// ListGroups gets a list of provisioned Groups for a Directory Endpoint.
func ListGroups(
	ctx context.Context,
	opts ListGroupsOpts,
) (ListGroupsResponse, error) {
	return DefaultClient.ListGroups(ctx, opts)
}

// GetUser gets a provisioned User for a Directory Endpoint.
func GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (DirectoryUser, error) {
	return DefaultClient.GetUser(ctx, opts)
}

// ListUserGroups gets details of a provisioned User's Groups for a Directory Endpoint.
func ListUserGroups(
	ctx context.Context,
	opts ListUserGroupsOpts,
) ([]DirectoryGroup, error) {
	return DefaultClient.ListUserGroups(ctx, opts)
}

// ListDirectories gets details of a Project's Directory Endpoints.
func ListDirectories(
	ctx context.Context,
	opts ListDirectoriesOpts,
) (ListDirectoriesResponse, error) {
	return DefaultClient.ListDirectories(ctx, opts)
}
