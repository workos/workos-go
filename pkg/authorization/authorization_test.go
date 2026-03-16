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
	response := ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object: "role_assignment",
				Id:     "ra_01ABC",
				Role:   RoleAssignmentRole{Slug: "admin"},
				Resource: RoleAssignmentResource{
					Id:               "resource_01ABC",
					ResourceTypeSlug: "document",
				},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{},
	}

	server := httptest.NewServer(http.HandlerFunc(
		jsonResponseHandler(nil, nil, response),
	))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	resp, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01ABC",
	})
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	require.Equal(t, "ra_01ABC", resp.Data[0].Id)
	require.Equal(t, "admin", resp.Data[0].Role.Slug)
}

func TestAuthorizationAssignRole(t *testing.T) {
	response := RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_01ABC",
		Role:   RoleAssignmentRole{Slug: "admin"},
		Resource: RoleAssignmentResource{
			Id:               "resource_01ABC",
			ResourceTypeSlug: "document",
		},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-02T00:00:00Z",
	}

	server := httptest.NewServer(http.HandlerFunc(
		jsonResponseHandler(nil, nil, response),
	))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	resp, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
	})
	require.NoError(t, err)
	require.Equal(t, "ra_01ABC", resp.Id)
	require.Equal(t, "admin", resp.Role.Slug)
}

func TestAuthorizationAssignRoleWithExternalId(t *testing.T) {
	response := RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_02DEF",
		Role:   RoleAssignmentRole{Slug: "viewer"},
		Resource: RoleAssignmentResource{
			ExternalId:       "ext_123",
			ResourceTypeSlug: "document",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(
		jsonResponseHandler(nil, nil, response),
	))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	resp, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "viewer",
		ResourceIdentifier: ResourceIdentifierByExternalId{
			ResourceExternalId: "ext_123",
			ResourceTypeSlug:   "document",
		},
	})
	require.NoError(t, err)
	require.Equal(t, "ra_02DEF", resp.Id)
	require.Equal(t, "ext_123", resp.Resource.ExternalId)
}

func TestAuthorizationRemoveRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		noContentHandler(nil, nil),
	))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		ResourceIdentifier:       ResourceIdentifierById{ResourceId: "resource_01ABC"},
	})
	require.NoError(t, err)
}

func TestAuthorizationRemoveRoleByExternalId(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		noContentHandler(nil, nil),
	))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleSlug:                 "admin",
		ResourceIdentifier: ResourceIdentifierByExternalId{
			ResourceExternalId: "ext_123",
			ResourceTypeSlug:   "document",
		},
	})
	require.NoError(t, err)
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		noContentHandler(nil, nil),
	))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01ABC",
		RoleAssignmentId:         "ra_01XYZ",
	})
	require.NoError(t, err)
}
