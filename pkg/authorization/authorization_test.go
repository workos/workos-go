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
	server := httptest.NewServer(http.HandlerFunc(listRoleAssignmentsTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	expectedResponse := ListRoleAssignmentsResponse{
		Data: []RoleAssignment{
			{
				Object: "role_assignment",
				Id:     "ra_01ABC",
				Role:   RoleAssignmentRole{Slug: "admin"},
				Resource: RoleAssignmentResource{
					Id:               "resource_01",
					ExternalId:       "ext-1",
					ResourceTypeSlug: "project",
				},
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-01-01T00:00:00Z",
			},
			{
				Object: "role_assignment",
				Id:     "ra_02DEF",
				Role:   RoleAssignmentRole{Slug: "viewer"},
				Resource: RoleAssignmentResource{
					Id:               "resource_02",
					ExternalId:       "ext-2",
					ResourceTypeSlug: "document",
				},
				CreatedAt: "2024-01-02T00:00:00Z",
				UpdatedAt: "2024-01-02T00:00:00Z",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "ra_02DEF",
		},
	}

	result, err := ListRoleAssignments(context.Background(), ListRoleAssignmentsOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		Limit:                    10,
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationAssignRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(assignRoleTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	expectedResponse := RoleAssignment{
		Object: "role_assignment",
		Id:     "ra_01ABC",
		Role:   RoleAssignmentRole{Slug: "admin"},
		Resource: RoleAssignmentResource{
			Id:               "resource_01",
			ResourceTypeSlug: "project",
		},
		CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}

	result, err := AssignRole(context.Background(), AssignRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_01"},
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, result)
}

func TestAuthorizationRemoveRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(removeRoleTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	err := RemoveRole(context.Background(), RemoveRoleOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleSlug:                 "admin",
		Resource:                 ResourceIdentifierById{ResourceId: "resource_01"},
	})

	require.NoError(t, err)
}

func TestAuthorizationRemoveRoleAssignment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(removeRoleAssignmentTestHandler))
	defer server.Close()

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: &retryablehttp.HttpClient{Client: *server.Client()},
	}
	SetAPIKey("test")

	err := RemoveRoleAssignment(context.Background(), RemoveRoleAssignmentOpts{
		OrganizationMembershipId: "om_01JKR3PB",
		RoleAssignmentId:         "ra_01ABC",
	})

	require.NoError(t, err)
}
