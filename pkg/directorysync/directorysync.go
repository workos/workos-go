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
//		directoryUsers, err := directorysync.ListDirectoryUsers(
//			context.Background(),
//			directorysync.ListDirectoryUsersOpts{
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

// ListDirectoryUsers gets a list of provisioned Users for a Directory Endpoint.
func ListDirectoryUsers(
	ctx context.Context,
	opts ListDirectoryUsersOpts,
) (ListDirectoryUsersResponse, error) {
	return DefaultClient.ListDirectoryUsers(ctx, opts)
}

// ListDirectoryGroups gets a list of provisioned Groups for a Directory Endpoint.
func ListDirectoryGroups(
	ctx context.Context,
	opts ListDirectoryGroupsOpts,
) (ListDirectoryGroupsResponse, error) {
	return DefaultClient.ListDirectoryGroups(ctx, opts)
}

// GetDirectoryUser gets a provisioned User for a Directory Endpoint.
func GetDirectoryUser(
	ctx context.Context,
	opts GetDirectoryUserOpts,
) (DirectoryUser, error) {
	return DefaultClient.GetDirectoryUser(ctx, opts)
}

// ListDirectoryUserGroups gets details of a provisioned User's Groups for a Directory Endpoint.
func ListDirectoryUserGroups(
	ctx context.Context,
	opts ListDirectoryUserGroupsOpts,
) ([]DirectoryGroup, error) {
	return DefaultClient.ListDirectoryUserGroups(ctx, opts)
}

// ListDirectories gets details of a Project's Directory Endpoints.
func ListDirectories(
	ctx context.Context,
	opts ListDirectoriesOpts,
) (ListDirectoriesResponse, error) {
	return DefaultClient.ListDirectories(ctx, opts)
}
