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
//		directoryUsers, err := directorysync.GetDirectoryUsers(
//			context.Background(),
//			directorysync.GetDirectoryUsersOpts{
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

// GetDirectoryUsers gets a list of provisioned Users for a Directory Endpoint.
func GetDirectoryUsers(
	ctx context.Context,
	opts GetDirectoryUsersOpts,
) (GetDirectoryUsersResponse, error) {
	return DefaultClient.GetDirectoryUsers(ctx, opts)
}

// GetDirectoryGroups gets a list of provisioned Groups for a Directory Endpoint.
func GetDirectoryGroups(
	ctx context.Context,
	opts GetDirectoryGroupsOpts,
) (GetDirectoryGroupsResponse, error) {
	return DefaultClient.GetDirectoryGroups(ctx, opts)
}

// GetDirectoryUser gets a provisioned User for a Directory Endpoint.
func GetDirectoryUser(
	ctx context.Context,
	opts GetDirectoryUserOpts,
) (DirectoryUser, error) {
	return DefaultClient.GetDirectoryUser(ctx, opts)
}

// GetDirectoryUserGroups gets details of a provisioned User's Groups for a Directory Endpoint.
func GetDirectoryUserGroups(
	ctx context.Context,
	opts GetDirectoryUserGroupsOpts,
) ([]DirectoryGroup, error) {
	return DefaultClient.GetDirectoryUserGroups(ctx, opts)
}

// GetDirectories gets details of a Project's Directory Endpoints.
func GetDirectories(
	ctx context.Context,
	opts GetDirectoriesOpts,
) (GetDirectoriesResponse, error) {
	return DefaultClient.GetDirectories(ctx, opts)
}
