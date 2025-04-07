package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func setup() {
	SetAPIKey("")
}

func TestCrudObjects(t *testing.T) {
	setup()

	buf := make([]byte, 16)
	rand.Read(buf)
	objectPrefix := hex.EncodeToString(buf)

	objectName := objectPrefix + "-lima"
	keyContext := KeyContext{"fiber": "Alpalca"}
	value := "Huacaya 27.7 micron"
	metadata := ObjectMetadata{}

	t.Run("create an object", func(t *testing.T) {
		result, err := CreateObject(context.Background(), CreateObjectOpts{
			Name:       objectName,
			Value:      value,
			KeyContext: keyContext,
		})
		require.NoError(t, err)
		require.Equal(t, keyContext, result.Context)

		metadata = result
	})

	t.Run("reads an object", func(t *testing.T) {
		object, err := ReadObject(context.Background(), ReadObjectOpts{Id: metadata.Id})
		require.NoError(t, err)
		require.Equal(t, objectName, object.Name)
		require.Equal(t, value, object.Value)
	})

	t.Run("fail to create object with existing name", func(t *testing.T) {
		_, err := CreateObject(context.Background(), CreateObjectOpts{
			Name:       objectName,
			Value:      value,
			KeyContext: keyContext,
		})
		require.Error(t, err)
	})

	t.Run("update existing object", func(t *testing.T) {
		newObjectName := objectPrefix + "-cusco"
		newMetadata, err := CreateObject(context.Background(), CreateObjectOpts{
			Name:       newObjectName,
			Value:      "Tapada 20-30 micron",
			KeyContext: keyContext,
		})
		require.NoError(t, err)

		newValue := "Ccara 30-40 micron"
		object, err := UpdateObject(context.Background(), UpdateObjectOpts{
			Id:    newMetadata.Id,
			Value: newValue,
		})
		require.NoError(t, err)
		require.Equal(t, newObjectName, object.Name)
		require.Equal(t, newMetadata.Id, object.Id)
		require.Equal(t, "", object.Value)

		object, err = ReadObject(context.Background(), ReadObjectOpts{Id: newMetadata.Id})
		require.NoError(t, err)
		require.Equal(t, newValue, object.Value)

	})

	t.Run("fails to update object with wrong version check", func(t *testing.T) {
		newValue := "Ccara 30-40 micron"
		object, err := UpdateObject(context.Background(), UpdateObjectOpts{
			Id:           metadata.Id,
			Value:        newValue,
			VersionCheck: metadata.VersionId,
		})
		require.NoError(t, err)

		_, err = UpdateObject(context.Background(), UpdateObjectOpts{
			Id:           metadata.Id,
			Value:        newValue + " updated",
			VersionCheck: metadata.VersionId,
		})
		require.Error(t, err)

		object, err = UpdateObject(context.Background(), UpdateObjectOpts{
			Id:           metadata.Id,
			Value:        newValue + " updated",
			VersionCheck: object.Metadata.VersionId,
		})
		require.NoError(t, err)
	})

	t.Run("delete object", func(t *testing.T) {
		newObjectName := objectPrefix + "-machu"
		newMetadata, err := CreateObject(context.Background(), CreateObjectOpts{
			Name:       newObjectName,
			Value:      "Tapada 20-30 micron",
			KeyContext: keyContext,
		})
		require.NoError(t, err)

		resp, err := DeleteObject(context.Background(), DeleteObjectOpts{Id: newMetadata.Id})
		require.NoError(t, err)
		require.True(t, resp.Success)

		_, err = ReadObject(context.Background(), ReadObjectOpts{Id: newMetadata.Id})
		require.ErrorContains(t, err, "Not Found")
	})

	t.Run("describe an object", func(t *testing.T) {
		object, err := DescribeObject(context.Background(), ReadObjectOpts{Id: metadata.Id})
		require.NoError(t, err)
		require.Equal(t, objectName, object.Name)
		require.Equal(t, "", object.Value)
		require.Equal(t, keyContext, object.Metadata.Context)
	})

	t.Run("lists objects with pagination", func(t *testing.T) {
		listResp, err := ListObjects(context.Background(), ListObjectsOpts{Limit: 2})
		require.NoError(t, err)
		require.Len(t, listResp.Data, 2)
		require.NotEqual(t, "", listResp.ListMetadata.Before)

		listResp2, err := ListObjects(context.Background(), ListObjectsOpts{
			Limit: 2,
			After: listResp.ListMetadata.Before,
		})
		require.NoError(t, err)
		require.NotElementsMatch(t, listResp.Data, listResp2.Data)
		require.NotEqual(t, listResp.ListMetadata.Before, listResp2.ListMetadata.Before)
	})
}

func TestDataKeys(t *testing.T) {
	setup()

	keyContext := KeyContext{"first": "comment"}
	dataKeyPair, err := CreateDataKey(context.Background(), CreateDataKeyOpts{KeyContext: keyContext})
	require.NoError(t, err)
	require.Equal(t, keyContext, dataKeyPair.KeyContext)
	require.NotEqual(t, "", dataKeyPair.EncryptedKeys)
	require.NotEqual(t, "", dataKeyPair.DataKey)

	dataKey, err := DecryptDataKey(context.Background(), DecryptDataKeyOpts{Keys: dataKeyPair.EncryptedKeys})
	require.NoError(t, err)
	require.Equal(t, dataKeyPair.DataKey, dataKey.Key)
}

func TestEncryption(t *testing.T) {
	setup()

	data := "hot water freezes faster than cold water"
	keyContext := KeyContext{"everything": "everywhere"}

	ciphertext, err := Encrypt(context.Background(), EncryptOpts{Data: data, KeyContext: keyContext})
	require.NoError(t, err)

	plaintext, err := Decrypt(context.Background(), DecryptOpts{Data: ciphertext})
	require.NoError(t, err)
	require.Equal(t, data, plaintext)
}
