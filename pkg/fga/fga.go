package fga

import "context"

// DefaultClient is the client used by SetAPIKey and FGA functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for FGA requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// GetObject gets an Object.
func GetObject(
	ctx context.Context,
	opts GetObjectOpts,
) (Object, error) {
	return DefaultClient.GetObject(ctx, opts)
}

// ListObjects gets a list of Objects.
func ListObjects(
	ctx context.Context,
	opts ListObjectsOpts,
) (ListObjectsResponse, error) {
	return DefaultClient.ListObjects(ctx, opts)
}

// CreateObject creates an Object.
func CreateObject(
	ctx context.Context,
	opts CreateObjectOpts,
) (Object, error) {
	return DefaultClient.CreateObject(ctx, opts)
}

// UpdateObject updates an Object.
func UpdateObject(
	ctx context.Context,
	opts UpdateObjectOpts,
) (Object, error) {
	return DefaultClient.UpdateObject(ctx, opts)
}

// DeleteObject deletes an Object.
func DeleteObject(
	ctx context.Context,
	opts DeleteObjectOpts,
) error {
	return DefaultClient.DeleteObject(ctx, opts)
}

// ListObjectTypes gets a list of ObjectTypes.
func ListObjectTypes(
	ctx context.Context,
	opts ListObjectTypesOpts,
) (ListObjectTypesResponse, error) {
	return DefaultClient.ListObjectTypes(ctx, opts)
}

// BatchUpdateObjectTypes sets the environment's object types to match the provided types.
func BatchUpdateObjectTypes(
	ctx context.Context,
	opts []UpdateObjectTypeOpts,
) ([]ObjectType, error) {
	return DefaultClient.BatchUpdateObjectTypes(ctx, opts)
}

// ListWarrants gets a list of Warrants.
func ListWarrants(
	ctx context.Context,
	opts ListWarrantsOpts,
) (ListWarrantsResponse, error) {
	return DefaultClient.ListWarrants(ctx, opts)
}

// WriteWarrant performs a write operation on a Warrant.
func WriteWarrant(
	ctx context.Context,
	opts WriteWarrantOpts,
) (WriteWarrantResponse, error) {
	return DefaultClient.WriteWarrant(ctx, opts)
}

// BatchWriteWarrants performs write operations on multiple Warrants in one request.
func BatchWriteWarrants(
	ctx context.Context,
	opts []WriteWarrantOpts,
) (WriteWarrantResponse, error) {
	return DefaultClient.BatchWriteWarrants(ctx, opts)
}

// Check performs an access check on a Warrant.
func Check(
	ctx context.Context,
	opts CheckOpts,
) (bool, error) {
	return DefaultClient.Check(ctx, opts)
}

// CheckMany performs access checks on multiple Warrants.
func CheckMany(
	ctx context.Context,
	opts CheckManyOpts,
) (bool, error) {
	return DefaultClient.CheckMany(ctx, opts)
}

// BatchCheck performs individual access checks on multiple Warrants in one request.
func BatchCheck(
	ctx context.Context,
	opts BatchCheckOpts,
) ([]bool, error) {
	return DefaultClient.BatchCheck(ctx, opts)
}

// Query performs a query for a set of resources.
func Query(
	ctx context.Context,
	opts QueryOpts,
) (QueryResponse, error) {
	return DefaultClient.Query(ctx, opts)
}
