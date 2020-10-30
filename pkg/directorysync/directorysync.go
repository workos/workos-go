// Package `directorysync` provides a client wrapping the WorkOS Directory Sync API.
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

// ListUsers gets a list of provisioned Users for a Directory.
func ListUsers(
	ctx context.Context,
	opts ListUsersOpts,
) (ListUsersResponse, error) {
	return DefaultClient.ListUsers(ctx, opts)
}

// ListGroups gets a list of provisioned Groups for a Directory.
func ListGroups(
	ctx context.Context,
	opts ListGroupsOpts,
) (ListGroupsResponse, error) {
	return DefaultClient.ListGroups(ctx, opts)
}

// GetUser gets a provisioned User for a Directory.
func GetUser(
	ctx context.Context,
	opts GetUserOpts,
) (User, error) {
	return DefaultClient.GetUser(ctx, opts)
}

// GetGroup gets a provisioned Group for a Directory.
func GetGroup(
	ctx context.Context,
	opts GetGroupOpts,
) (Group, error) {
	return DefaultClient.GetGroup(ctx, opts)
}

// ListDirectories gets details of a Project's Directories.
func ListDirectories(
	ctx context.Context,
	opts ListDirectoriesOpts,
) (ListDirectoriesResponse, error) {
	return DefaultClient.ListDirectories(ctx, opts)
}
