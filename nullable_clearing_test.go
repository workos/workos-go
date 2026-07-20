package workos_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v9"
)

// These tests verify the oagen-generated NullFields / MarshalJSON behavior for
// clearing nullable fields:
//   - a concrete pointer serializes as its value
//   - a nil pointer not listed in NullFields is omitted
//   - a field listed in NullFields serializes as explicit JSON null
//   - an unknown / non-nullable NullFields entry returns a marshal error
//   - NullFields itself never appears in the JSON output

func TestNullableClearing_ConcreteValue(t *testing.T) {
	data, err := json.Marshal(workos.OrganizationsUpdateParams{
		ExternalID: workos.String("ext-123"),
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	require.Equal(t, "ext-123", m["external_id"])
	require.NotContains(t, m, "NullFields")
}

func TestNullableClearing_OmittedNilPointer(t *testing.T) {
	data, err := json.Marshal(workos.OrganizationsUpdateParams{})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	require.NotContains(t, m, "external_id")
	require.NotContains(t, m, "NullFields")
}

func TestNullableClearing_ExplicitNull(t *testing.T) {
	data, err := json.Marshal(workos.OrganizationsUpdateParams{
		NullFields: []string{"external_id"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	require.Contains(t, m, "external_id")
	require.Nil(t, m["external_id"])
	require.NotContains(t, m, "NullFields")
}

func TestNullableClearing_InvalidField(t *testing.T) {
	_, err := json.Marshal(workos.OrganizationsUpdateParams{
		NullFields: []string{"not_a_real_field"},
	})
	require.Error(t, err)
}

func TestNullableClearing_SentinelNeverLeaks(t *testing.T) {
	data, err := json.Marshal(workos.OrganizationsUpdateParams{
		Name:       workos.String("New Name"),
		NullFields: []string{"external_id"},
	})
	require.NoError(t, err)
	require.NotContains(t, string(data), "NullFields")
}

func TestNullableClearing_User(t *testing.T) {
	data, err := json.Marshal(workos.UserManagementUpdateParams{
		NullFields: []string{"external_id"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	require.Contains(t, m, "external_id")
	require.Nil(t, m["external_id"])
}
