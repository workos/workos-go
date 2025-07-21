package common

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserMarshalUnmarshal(t *testing.T) {
	user := User{
		ID:                "user_123",
		Email:             "test@example.com",
		FirstName:         "John",
		LastName:          "Doe",
		EmailVerified:     true,
		ProfilePictureURL: "https://example.com/avatar.jpg",
		CreatedAt:         "2023-01-01T00:00:00Z",
		UpdatedAt:         "2023-01-02T00:00:00Z",
		LastSignInAt:      "2023-01-03T00:00:00Z",
		ExternalID:        "ext_123",
		Metadata: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(user)
	require.NoError(t, err)

	// Unmarshal back to struct
	var unmarshaledUser User
	err = json.Unmarshal(data, &unmarshaledUser)
	require.NoError(t, err)

	// Verify all fields are preserved
	require.Equal(t, user.ID, unmarshaledUser.ID)
	require.Equal(t, user.Email, unmarshaledUser.Email)
	require.Equal(t, user.FirstName, unmarshaledUser.FirstName)
	require.Equal(t, user.LastName, unmarshaledUser.LastName)
	require.Equal(t, user.EmailVerified, unmarshaledUser.EmailVerified)
	require.Equal(t, user.ProfilePictureURL, unmarshaledUser.ProfilePictureURL)
	require.Equal(t, user.CreatedAt, unmarshaledUser.CreatedAt)
	require.Equal(t, user.UpdatedAt, unmarshaledUser.UpdatedAt)
	require.Equal(t, user.LastSignInAt, unmarshaledUser.LastSignInAt)
	require.Equal(t, user.ExternalID, unmarshaledUser.ExternalID)
	require.Equal(t, user.Metadata, unmarshaledUser.Metadata)
}
