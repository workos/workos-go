// @oagen-ignore-file

package workos

import (
	"context"
	"fmt"
)

// VaultService handles Vault operations.
type VaultService struct {
	client *Client
}

// KeyContext describes the encryption context for a vault key.
type KeyContext struct {
	// Type is the key context type (e.g., "environment").
	Type string `json:"type"`
	// EnvironmentID is the WorkOS environment ID this key is scoped to.
	EnvironmentID string `json:"environment_id"`
}

// ObjectMetadata contains metadata about a vault object.
type ObjectMetadata struct {
	// Context is the encryption key context used for this object.
	Context KeyContext `json:"context"`
	// EnvironmentID is the WorkOS environment ID.
	EnvironmentID string `json:"environment_id"`
	// ID is the unique identifier of the vault object.
	ID string `json:"id"`
	// KeyID is the identifier of the encryption key used.
	KeyID string `json:"key_id"`
	// UpdatedAt is the ISO-8601 timestamp of the last update.
	UpdatedAt string `json:"updated_at"`
	// UpdatedBy is the identifier of the actor who last updated the object.
	UpdatedBy string `json:"updated_by"`
	// VersionID is the current version identifier.
	VersionID string `json:"version_id"`
}

// VaultObject represents a vault key-value object.
type VaultObject struct {
	ID       string          `json:"id"`
	Metadata *ObjectMetadata `json:"metadata,omitempty"`
	Name     string          `json:"name"`
	Value    *string         `json:"value,omitempty"`
}

// VaultObjectDigest is a summary representation of a vault object.
type VaultObjectDigest struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	EnvironmentID string  `json:"environment_id"`
	UpdatedAt     string  `json:"updated_at"`
	VersionID     *string `json:"version_id,omitempty"`
}

// VaultObjectVersion represents a specific version of a vault object.
type VaultObjectVersion struct {
	VersionID string `json:"version_id"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

// DataKeyPair contains an encryption data key and its encrypted counterpart.
type DataKeyPair struct {
	// Context is the encryption key context for this data key.
	Context KeyContext `json:"context"`
	// DataKey is the plaintext data key for local encryption/decryption.
	DataKey DataKey `json:"data_key"`
	// EncryptedKeys is the base64-encoded encrypted key blob for server-side decryption.
	EncryptedKeys string `json:"encrypted_keys"`
}

// DataKey holds a plaintext data key.
type DataKey struct {
	// Key is the base64-encoded plaintext AES key.
	Key string `json:"key"`
}

// VaultListObjectsParams contains the parameters for ListObjects.
type VaultListObjectsParams struct {
	IncludeValues *string `url:"include_values,omitempty" json:"-"`
}

// VaultListObjectsResponse is the response from ListObjects.
type VaultListObjectsResponse struct {
	Data []VaultObjectDigest `json:"data"`
}

// ListObjects lists vault objects (GET /vault/v1/kv).
func (s *VaultService) ListObjects(ctx context.Context, params *VaultListObjectsParams, opts ...RequestOption) (*VaultListObjectsResponse, error) {
	var result VaultListObjectsResponse
	_, err := s.client.request(ctx, "GET", "/vault/v1/kv", params, nil, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// VaultCreateObjectParams contains the parameters for CreateObject.
type VaultCreateObjectParams struct {
	Name        string      `json:"name"`
	Value       string      `json:"value"`
	KeyContext  *KeyContext `json:"key_context,omitempty"`
	Description *string     `json:"description,omitempty"`
}

// CreateObject creates a new vault object (POST /vault/v1/kv).
func (s *VaultService) CreateObject(ctx context.Context, params *VaultCreateObjectParams, opts ...RequestOption) (*ObjectMetadata, error) {
	var result ObjectMetadata
	_, err := s.client.request(ctx, "POST", "/vault/v1/kv", nil, params, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ReadObject reads a vault object by ID (GET /vault/v1/kv/{id}).
func (s *VaultService) ReadObject(ctx context.Context, objectID string, opts ...RequestOption) (*VaultObject, error) {
	var result VaultObject
	_, err := s.client.request(ctx, "GET", fmt.Sprintf("/vault/v1/kv/%s", objectID), nil, nil, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ReadObjectByName reads a vault object by name (GET /vault/v1/kv/name/{name}).
func (s *VaultService) ReadObjectByName(ctx context.Context, name string, opts ...RequestOption) (*VaultObject, error) {
	var result VaultObject
	_, err := s.client.request(ctx, "GET", fmt.Sprintf("/vault/v1/kv/name/%s", name), nil, nil, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DescribeObject retrieves metadata for a vault object (GET /vault/v1/kv/{id}/metadata).
func (s *VaultService) DescribeObject(ctx context.Context, objectID string, opts ...RequestOption) (*VaultObject, error) {
	var result VaultObject
	_, err := s.client.request(ctx, "GET", fmt.Sprintf("/vault/v1/kv/%s/metadata", objectID), nil, nil, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// VaultUpdateObjectParams contains the parameters for UpdateObject.
type VaultUpdateObjectParams struct {
	Value       string      `json:"value"`
	KeyContext  *KeyContext `json:"key_context,omitempty"`
	Description *string     `json:"description,omitempty"`
}

// UpdateObject updates a vault object (PUT /vault/v1/kv/{id}).
func (s *VaultService) UpdateObject(ctx context.Context, objectID string, params *VaultUpdateObjectParams, opts ...RequestOption) (*VaultObject, error) {
	var result VaultObject
	_, err := s.client.request(ctx, "PUT", fmt.Sprintf("/vault/v1/kv/%s", objectID), nil, params, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteObject deletes a vault object (DELETE /vault/v1/kv/{id}).
func (s *VaultService) DeleteObject(ctx context.Context, objectID string, opts ...RequestOption) error {
	_, err := s.client.request(ctx, "DELETE", fmt.Sprintf("/vault/v1/kv/%s", objectID), nil, nil, nil, opts)
	return err
}

// VaultListObjectVersionsResponse is the response from ListObjectVersions.
type VaultListObjectVersionsResponse struct {
	Data []VaultObjectVersion `json:"data"`
}

// ListObjectVersions lists versions of a vault object (GET /vault/v1/kv/{id}/versions).
func (s *VaultService) ListObjectVersions(ctx context.Context, objectID string, opts ...RequestOption) ([]VaultObjectVersion, error) {
	var result VaultListObjectVersionsResponse
	_, err := s.client.request(ctx, "GET", fmt.Sprintf("/vault/v1/kv/%s/versions", objectID), nil, nil, &result, opts)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

// VaultCreateDataKeyParams contains the parameters for CreateDataKey.
type VaultCreateDataKeyParams struct {
	Context KeyContext `json:"context"`
}

// CreateDataKey creates a new data key pair (POST /vault/v1/keys/data-key).
func (s *VaultService) CreateDataKey(ctx context.Context, params *VaultCreateDataKeyParams, opts ...RequestOption) (*DataKeyPair, error) {
	var result DataKeyPair
	_, err := s.client.request(ctx, "POST", "/vault/v1/keys/data-key", nil, params, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// VaultDecryptDataKeyParams contains the parameters for DecryptDataKey.
type VaultDecryptDataKeyParams struct {
	Context       KeyContext `json:"context"`
	EncryptedKeys string     `json:"encrypted_keys"`
}

// DecryptDataKey decrypts a data key (POST /vault/v1/keys/decrypt).
func (s *VaultService) DecryptDataKey(ctx context.Context, params *VaultDecryptDataKeyParams, opts ...RequestOption) (*DataKey, error) {
	var result DataKey
	_, err := s.client.request(ctx, "POST", "/vault/v1/keys/decrypt", nil, params, &result, opts)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
