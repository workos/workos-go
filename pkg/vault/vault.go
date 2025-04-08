package vault

import "context"

// DefaultClient is the client used by SetAPIKey and Vault functions.
var (
	DefaultClient = &Client{
		Endpoint: "https://api.workos.com",
	}
)

// SetAPIKey sets the WorkOS API key for Vault requests.
func SetAPIKey(apiKey string) {
	DefaultClient.APIKey = apiKey
}

// ListObjects gets a list of Objects.
func ListObjects(
	ctx context.Context,
	opts ListObjectsOpts,
) (ListObjectsResponse, error) {
	return DefaultClient.ListObjects(ctx, opts)
}

// CreateObject create a new encrypted Object.
func CreateObject(
	ctx context.Context,
	opts CreateObjectOpts,
) (ObjectMetadata, error) {
	return DefaultClient.CreateObject(ctx, opts)
}

// ListObjectVersions gets a list of versions for an Object.
func ListObjectVersions(
	ctx context.Context,
	opts ReadObjectOpts,
) (ListObjectVersionsResponse, error) {
	return DefaultClient.ListObjectVersions(ctx, opts)
}

// ReadObject gets an Object with its decrypted value.
func ReadObject(
	ctx context.Context,
	opts ReadObjectOpts,
) (Object, error) {
	return DefaultClient.ReadObject(ctx, opts)
}

// DescribeObject gets metadata about an object, withthout the value.
func DescribeObject(
	ctx context.Context,
	opts ReadObjectOpts,
) (Object, error) {
	return DefaultClient.DescribeObject(ctx, opts)
}

// UpdateObject write a new value for an existing Object.
func UpdateObject(
	ctx context.Context,
	opts UpdateObjectOpts,
) (Object, error) {
	return DefaultClient.UpdateObject(ctx, opts)
}

// DeleteObject deletes an stored Object.
func DeleteObject(
	ctx context.Context,
	opts DeleteObjectOpts,
) (DeleteObjectResponse, error) {
	return DefaultClient.DeleteObject(ctx, opts)
}

// CreateDataKey generates a data key for local encryption.
func CreateDataKey(
	ctx context.Context,
	opts CreateDataKeyOpts,
) (DataKeyPair, error) {
	return DefaultClient.CreateDataKey(ctx, opts)
}

// DecryptDataKey decrypt a data key that was previously encrypted using Vault.
func DecryptDataKey(
	ctx context.Context,
	opts DecryptDataKeyOpts,
) (DataKey, error) {
	return DefaultClient.DecryptDataKey(ctx, opts)
}

// Encrypt performs a local encryption using keys from Vault.
func Encrypt(
	ctx context.Context,
	opts EncryptOpts,
) (string, error) {
	dataKeyOpts := CreateDataKeyOpts{KeyContext: opts.KeyContext}
	dataKeyPair, err := DefaultClient.CreateDataKey(ctx, dataKeyOpts)
	if err != nil {
		return "", err
	}

	return LocalEncrypt(opts.Data, dataKeyPair)
}

// Decrypt perfroms a local decryption of data that was previously encrypted with Vault.
func Decrypt(
	ctx context.Context,
	opts DecryptOpts,
) (string, error) {
	decoded, err := Decode(opts.Data)
	if err != nil {
		return "", err
	}

	dataKeyOpts := DecryptDataKeyOpts{Keys: decoded.Keys}
	dataKey, err := DefaultClient.DecryptDataKey(ctx, dataKeyOpts)
	if err != nil {
		return "", err
	}

	return LocalDecrypt(decoded, dataKey)
}
