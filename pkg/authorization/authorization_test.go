package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/retryablehttp"
)

func TestAuthorizationListRoleAssignments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object:    "role_assignment",
				Id:        "ra_01ABC",
				Role:      RoleAssignmentRole{Slug: "admin"},
				Resource:  RoleAssignmentResource{Id: "resource_01", ResourceTypeSlug: "project"},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "ra_01ABC"},
	})))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object:    "role_assignment",
				Id:        "ra_01ABC",
				Role:      RoleAssignmentRole{Slug: "admin"},
				Resource:  RoleAssignmentResource{Id: "resource_01", ResourceTypeSlug: "project"},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{After: "ra_01ABC"},
	}

	result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01JKR3PB",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationAssignRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, RoleAssignment{
		Object:    "role_assignment",
		Id:        "ra_01ABC",
		Role:      RoleAssignmentRole{Slug: "admin"},
		Resource:  RoleAssignmentResource{Id: "resource_01", ResourceTypeSlug: "project"},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	})))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := RoleAssignment{
		Object:    "role_assignment",
		Id:        "ra_01ABC",
		Role:      RoleAssignmentRole{Slug: "admin"},
		Resource:  RoleAssignmentResource{Id: "resource_01", ResourceTypeSlug: "project"},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}

	result, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "admin",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationAssignRoleWithExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(jsonResponseHandler(nil, nil, RoleAssignment{
		Object:    "role_assignment",
		Id:        "ra_01ABC",
		Role:      RoleAssignmentRole{Slug: "admin"},
		Resource:  RoleAssignmentResource{ExternalId: "ext-resource-42", ResourceTypeSlug: "document"},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	})))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	expectedResponse := RoleAssignment{
		Object:    "role_assignment",
		Id:        "ra_01ABC",
		Role:      RoleAssignmentRole{Slug: "admin"},
		Resource:  RoleAssignmentResource{ExternalId: "ext-resource-42", ResourceTypeSlug: "document"},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}

	result, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "admin",
		ResourceIdentifier:       ResourceIdentifierByExternalId{ResourceExternalId: "ext-resource-42", ResourceTypeSlug: "document"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationRemoveRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, nil)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "admin",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01"},
	})

	require.NoError(t, err)
}

func TestAuthorizationRemoveRoleByExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, nil)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "admin",
		ResourceIdentifier:       ResourceIdentifierByExternalId{ResourceExternalId: "ext-resource-42", ResourceTypeSlug: "document"},
	})

	require.NoError(t, err)
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(noContentHandler(nil, nil)))
	defer server.Close()

	DefaultClient = &Client{
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
		Endpoint:   server.URL,
	}
	SetAPIKey("test")

	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleAssignmentId:         "ra_01ABC",
	})

	require.NoError(t, err)
}
