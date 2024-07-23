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

// GetResource gets a Resource.
func GetResource(
	ctx context.Context,
	opts GetResourceOpts,
) (Resource, error) {
	return DefaultClient.GetResource(ctx, opts)
}

// ListResources gets a list of Resources.
func ListResources(
	ctx context.Context,
	opts ListResourcesOpts,
) (ListResourcesResponse, error) {
	return DefaultClient.ListResources(ctx, opts)
}

// CreateResource creates a Resource.
func CreateResource(
	ctx context.Context,
	opts CreateResourceOpts,
) (Resource, error) {
	return DefaultClient.CreateResource(ctx, opts)
}

// UpdateResource updates a Resource.
func UpdateResource(
	ctx context.Context,
	opts UpdateResourceOpts,
) (Resource, error) {
	return DefaultClient.UpdateResource(ctx, opts)
}

// DeleteResource deletes a Resource.
func DeleteResource(
	ctx context.Context,
	opts DeleteResourceOpts,
) error {
	return DefaultClient.DeleteResource(ctx, opts)
}

// ListResourceTypes gets a list of ResourceTypes.
func ListResourceTypes(
	ctx context.Context,
	opts ListResourceTypesOpts,
) (ListResourceTypesResponse, error) {
	return DefaultClient.ListResourceTypes(ctx, opts)
}

// BatchUpdateResourceTypes sets the environment's object types to match the provided types.
func BatchUpdateResourceTypes(
	ctx context.Context,
	opts []UpdateResourceTypeOpts,
) ([]ResourceType, error) {
	return DefaultClient.BatchUpdateResourceTypes(ctx, opts)
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

// Check performs access checks on multiple Warrants.
func Check(
	ctx context.Context,
	opts CheckOpts,
) (CheckResponse, error) {
	return DefaultClient.Check(ctx, opts)
}

// CheckBatch performs individual access checks on multiple Warrants in one request.
func CheckBatch(
	ctx context.Context,
	opts CheckBatchOpts,
) ([]CheckResponse, error) {
	return DefaultClient.CheckBatch(ctx, opts)
}

// Query performs a query for a set of resources.
func Query(
	ctx context.Context,
	opts QueryOpts,
) (QueryResponse, error) {
	return DefaultClient.Query(ctx, opts)
}
