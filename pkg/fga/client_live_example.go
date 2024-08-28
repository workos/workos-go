package fga

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func setup() {
	SetAPIKey("")
}

func TestCrudResources(t *testing.T) {
	setup()

	resource1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "document",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "document", resource1.ResourceType)
	require.NotEmpty(t, resource1.ResourceId)
	require.Empty(t, resource1.Meta)

	resource2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "folder",
		ResourceId:   "planning",
	})
	if err != nil {
		t.Fatal(err)
	}
	refetchedResource, err := GetResource(context.Background(), GetResourceOpts{
		ResourceType: resource2.ResourceType,
		ResourceId:   resource2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, resource2.ResourceType, refetchedResource.ResourceType)
	require.Equal(t, resource2.ResourceId, refetchedResource.ResourceId)
	require.EqualValues(t, resource2.Meta, refetchedResource.Meta)

	resource2, err = UpdateResource(context.Background(), UpdateResourceOpts{
		ResourceType: resource2.ResourceType,
		ResourceId:   resource2.ResourceId,
		Meta: map[string]interface{}{
			"description": "Folder resource",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	refetchedResource, err = GetResource(context.Background(), GetResourceOpts{
		ResourceType: resource2.ResourceType,
		ResourceId:   resource2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, resource2.ResourceType, refetchedResource.ResourceType)
	require.Equal(t, resource2.ResourceId, refetchedResource.ResourceId)
	require.EqualValues(t, resource2.Meta, refetchedResource.Meta)

	resourcesList, err := ListResources(context.Background(), ListResourcesOpts{
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, resourcesList.Data, 2)
	require.Equal(t, resource2.ResourceType, resourcesList.Data[0].ResourceType)
	require.Equal(t, resource2.ResourceId, resourcesList.Data[0].ResourceId)
	require.Equal(t, resource1.ResourceType, resourcesList.Data[1].ResourceType)
	require.Equal(t, resource1.ResourceId, resourcesList.Data[1].ResourceId)

	// Sort in ascending order
	resourcesList, err = ListResources(context.Background(), ListResourcesOpts{
		Limit: 10,
		Order: Asc,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, resourcesList.Data, 2)
	require.Equal(t, resource1.ResourceType, resourcesList.Data[0].ResourceType)
	require.Equal(t, resource1.ResourceId, resourcesList.Data[0].ResourceId)
	require.Equal(t, resource2.ResourceType, resourcesList.Data[1].ResourceType)
	require.Equal(t, resource2.ResourceId, resourcesList.Data[1].ResourceId)

	resourcesList, err = ListResources(context.Background(), ListResourcesOpts{
		Limit:  10,
		Search: "planning",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, resourcesList.Data, 1)
	require.Equal(t, resource2.ResourceType, resourcesList.Data[0].ResourceType)
	require.Equal(t, resource2.ResourceId, resourcesList.Data[0].ResourceId)

	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: resource1.ResourceType,
		ResourceId:   resource1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: resource2.ResourceType,
		ResourceId:   resource2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourcesList, err = ListResources(context.Background(), ListResourcesOpts{
		Limit:  10,
		Search: "planning",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, resourcesList.Data, 0)
}

func TestMultiTenancy(t *testing.T) {
	setup()

	// Create users
	user1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	user2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create tenants
	tenant1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "tenant",
		ResourceId:   "tenant-1",
		Meta: map[string]interface{}{
			"name": "Tenant 1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tenant2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "tenant",
		ResourceId:   "tenant-2",
		Meta: map[string]interface{}{
			"name": "Tenant 2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	user1TenantsList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select tenant where user:%s is member", user1.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, user1TenantsList.Data, 0)
	tenant1UsersList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select member of type user for tenant:%s", tenant1.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, tenant1UsersList.Data, 0)

	// Assign user1 -> tenant1
	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: tenant1.ResourceType,
		ResourceId:   tenant1.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: user1.ResourceType,
			ResourceId:   user1.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	user1TenantsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select tenant where user:%s is member", user1.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, user1TenantsList.Data, 1)
	require.Equal(t, "tenant", user1TenantsList.Data[0].ResourceType)
	require.Equal(t, "tenant-1", user1TenantsList.Data[0].ResourceId)
	require.EqualValues(t, map[string]interface{}{
		"name": "Tenant 1",
	}, user1TenantsList.Data[0].Meta)

	tenant1UsersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select member of type user for tenant:%s", tenant1.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, tenant1UsersList.Data, 1)
	require.Equal(t, "user", tenant1UsersList.Data[0].ResourceType)
	require.Equal(t, user1.ResourceId, tenant1UsersList.Data[0].ResourceId)
	require.Empty(t, tenant1UsersList.Data[0].Meta)

	// Remove user1 -> tenant1
	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: tenant1.ResourceType,
		ResourceId:   tenant1.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: user1.ResourceType,
			ResourceId:   user1.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	user1TenantsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select tenant where user:%s is member", user1.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, user1TenantsList.Data, 0)
	tenant1UsersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select member of type user for tenant:%s", tenant1.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, tenant1UsersList.Data, 0)

	// Clean up
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: user1.ResourceType,
		ResourceId:   user1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: user2.ResourceType,
		ResourceId:   user2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: tenant1.ResourceType,
		ResourceId:   tenant1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: tenant2.ResourceType,
		ResourceId:   tenant2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRBAC(t *testing.T) {
	setup()

	// Create users
	adminUser, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	viewerUser, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create roles
	adminRole, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "role",
		ResourceId:   "administrator",
		Meta: map[string]interface{}{
			"name":        "Administrator",
			"description": "The admin role",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	viewerRole, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "role",
		ResourceId:   "viewer",
		Meta: map[string]interface{}{
			"name":        "Viewer",
			"description": "The viewer role",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create permissions
	createPermission, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "create-report",
		Meta: map[string]interface{}{
			"name":        "Create Report",
			"description": "Permission to create reports",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	viewPermission, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "view-report",
		Meta: map[string]interface{}{
			"name":        "View Report",
			"description": "Permission to view reports",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	adminUserRolesList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select role where user:%s is member", adminUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminUserRolesList.Data, 0)

	adminRolePermissionsList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where role:%s is member", adminRole.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminRolePermissionsList.Data, 0)

	adminUserHasPermission, err := Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: createPermission.ResourceType,
				ResourceId:   createPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: adminUser.ResourceType,
					ResourceId:   adminUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, adminUserHasPermission.Authorized())

	// Assign create-report permission -> admin role -> admin user
	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: createPermission.ResourceType,
		ResourceId:   createPermission.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: adminRole.ResourceType,
			ResourceId:   adminRole.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: adminRole.ResourceType,
		ResourceId:   adminRole.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: adminUser.ResourceType,
			ResourceId:   adminUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	adminUserHasPermission, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: createPermission.ResourceType,
				ResourceId:   createPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: adminUser.ResourceType,
					ResourceId:   adminUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, adminUserHasPermission.Authorized())

	adminUserRolesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select role where user:%s is member", adminUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminUserRolesList.Data, 1)
	require.Equal(t, "role", adminUserRolesList.Data[0].ResourceType)
	require.Equal(t, adminRole.ResourceId, adminUserRolesList.Data[0].ResourceId)
	require.Equal(t, map[string]interface{}{
		"name":        "Administrator",
		"description": "The admin role",
	}, adminUserRolesList.Data[0].Meta)

	adminRolePermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where role:%s is member", adminRole.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminRolePermissionsList.Data, 1)
	require.Equal(t, "permission", adminRolePermissionsList.Data[0].ResourceType)
	require.Equal(t, createPermission.ResourceId, adminRolePermissionsList.Data[0].ResourceId)
	require.Equal(t, map[string]interface{}{
		"name":        "Create Report",
		"description": "Permission to create reports",
	}, adminRolePermissionsList.Data[0].Meta)

	// Remove create-report permission -> admin role -> admin user
	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: createPermission.ResourceType,
		ResourceId:   createPermission.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: adminRole.ResourceType,
			ResourceId:   adminRole.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: adminRole.ResourceType,
		ResourceId:   adminRole.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: adminUser.ResourceType,
			ResourceId:   adminUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	adminUserHasPermission, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: createPermission.ResourceType,
				ResourceId:   createPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: adminUser.ResourceType,
					ResourceId:   adminUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, adminUserHasPermission.Authorized())

	adminUserRolesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select role where user:%s is member", adminUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminUserRolesList.Data, 0)

	adminRolePermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where role:%s is member", adminRole.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminRolePermissionsList.Data, 0)

	// Assign view-report -> viewer user
	viewerUserHasPermission, err := Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: viewPermission.ResourceType,
				ResourceId:   viewPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: viewerUser.ResourceType,
					ResourceId:   viewerUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, viewerUserHasPermission.Authorized())

	viewerUserPermissionsList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", viewerUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, viewerUserPermissionsList.Data)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: viewPermission.ResourceType,
		ResourceId:   viewPermission.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: viewerUser.ResourceType,
			ResourceId:   viewerUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	viewerUserHasPermission, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: viewPermission.ResourceType,
				ResourceId:   viewPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: viewerUser.ResourceType,
					ResourceId:   viewerUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, viewerUserHasPermission.Authorized())

	viewerUserPermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", viewerUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, viewerUserPermissionsList.Data, 1)
	require.Equal(t, "permission", viewerUserPermissionsList.Data[0].ResourceType)
	require.Equal(t, viewPermission.ResourceId, viewerUserPermissionsList.Data[0].ResourceId)
	require.Equal(t, map[string]interface{}{
		"name":        "View Report",
		"description": "Permission to view reports",
	}, viewerUserPermissionsList.Data[0].Meta)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: viewPermission.ResourceType,
		ResourceId:   viewPermission.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: viewerUser.ResourceType,
			ResourceId:   viewerUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	viewerUserHasPermission, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: viewPermission.ResourceType,
				ResourceId:   viewPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: viewerUser.ResourceType,
					ResourceId:   viewerUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, viewerUserHasPermission.Authorized())

	viewerUserPermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", viewerUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, viewerUserPermissionsList.Data)

	// Clean up
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: adminUser.ResourceType,
		ResourceId:   adminUser.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: viewerUser.ResourceType,
		ResourceId:   viewerUser.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: adminRole.ResourceType,
		ResourceId:   adminRole.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: viewerRole.ResourceType,
		ResourceId:   viewerRole.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: createPermission.ResourceType,
		ResourceId:   createPermission.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: viewPermission.ResourceType,
		ResourceId:   viewPermission.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPricingTiersFeaturesAndUsers(t *testing.T) {
	setup()

	// Create users
	freeUser, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	paidUser, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create pricing tiers
	freeTier, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "pricing-tier",
		ResourceId:   "free",
		Meta: map[string]interface{}{
			"name": "Free Tier",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	paidTier, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "pricing-tier",
		ResourceId:   "paid",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create features
	customFeature, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "feature",
		ResourceId:   "custom",
		Meta: map[string]interface{}{
			"name": "Custom Feature",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	feature1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "feature",
		ResourceId:   "feature-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	feature2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "feature",
		ResourceId:   "feature-2",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Assign custom-feature -> paid user
	paidUserHasFeature, err := Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: customFeature.ResourceType,
				ResourceId:   customFeature.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: paidUser.ResourceType,
					ResourceId:   paidUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, paidUserHasFeature.Authorized())

	paidUserFeaturesList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", paidUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, paidUserFeaturesList.Data)

	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: customFeature.ResourceType,
		ResourceId:   customFeature.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: paidUser.ResourceType,
			ResourceId:   paidUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	paidUserHasFeature, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: customFeature.ResourceType,
				ResourceId:   customFeature.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: paidUser.ResourceType,
					ResourceId:   paidUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, paidUserHasFeature.Authorized())

	paidUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", paidUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, paidUserFeaturesList.Data, 1)
	require.Equal(t, "feature", paidUserFeaturesList.Data[0].ResourceType)
	require.Equal(t, customFeature.ResourceId, paidUserFeaturesList.Data[0].ResourceId)
	require.Equal(t, map[string]interface{}{
		"name": "Custom Feature",
	}, paidUserFeaturesList.Data[0].Meta)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: customFeature.ResourceType,
		ResourceId:   customFeature.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: paidUser.ResourceType,
			ResourceId:   paidUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	paidUserHasFeature, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: customFeature.ResourceType,
				ResourceId:   customFeature.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: paidUser.ResourceType,
					ResourceId:   paidUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, paidUserHasFeature.Authorized())

	paidUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", paidUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, paidUserFeaturesList.Data)

	// Assign feature-1 -> free tier -> free user
	freeUserHasFeature, err := Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: feature1.ResourceType,
				ResourceId:   feature1.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: freeUser.ResourceType,
					ResourceId:   freeUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, freeUserHasFeature.Authorized())

	freeUserFeaturesList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", freeUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, freeUserFeaturesList.Data)

	featureUserTiersList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select pricing-tier where user:%s is member", freeUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, featureUserTiersList.Data)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: feature1.ResourceType,
		ResourceId:   feature1.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: freeTier.ResourceType,
			ResourceId:   freeTier.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: freeTier.ResourceType,
		ResourceId:   freeTier.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: freeUser.ResourceType,
			ResourceId:   freeUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	freeUserHasFeature, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: feature1.ResourceType,
				ResourceId:   feature1.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: freeUser.ResourceType,
					ResourceId:   freeUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, freeUserHasFeature.Authorized())

	freeUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", freeUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, freeUserFeaturesList.Data, 1)
	require.Equal(t, "feature", freeUserFeaturesList.Data[0].ResourceType)
	require.Equal(t, feature1.ResourceId, freeUserFeaturesList.Data[0].ResourceId)
	require.Empty(t, freeUserFeaturesList.Data[0].Meta)

	featureUserTiersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select pricing-tier where user:%s is member", freeUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, featureUserTiersList.Data, 1)
	require.Equal(t, "pricing-tier", featureUserTiersList.Data[0].ResourceType)
	require.Equal(t, freeTier.ResourceId, featureUserTiersList.Data[0].ResourceId)
	require.Equal(t, map[string]interface{}{
		"name": "Free Tier",
	}, featureUserTiersList.Data[0].Meta)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: feature1.ResourceType,
		ResourceId:   feature1.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: freeTier.ResourceType,
			ResourceId:   freeTier.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: freeTier.ResourceType,
		ResourceId:   freeTier.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: freeUser.ResourceType,
			ResourceId:   freeUser.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	freeUserHasFeature, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: feature1.ResourceType,
				ResourceId:   feature1.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: freeUser.ResourceType,
					ResourceId:   freeUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, freeUserHasFeature.Authorized())

	freeUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", freeUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, freeUserFeaturesList.Data)

	featureUserTiersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select pricing-tier where user:%s is member", freeUser.ResourceId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, featureUserTiersList.Data)

	// Clean up
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: freeUser.ResourceType,
		ResourceId:   freeUser.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: paidUser.ResourceType,
		ResourceId:   paidUser.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: freeTier.ResourceType,
		ResourceId:   freeTier.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: paidTier.ResourceType,
		ResourceId:   paidTier.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: customFeature.ResourceType,
		ResourceId:   customFeature.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: feature1.ResourceType,
		ResourceId:   feature1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: feature2.ResourceType,
		ResourceId:   feature2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWarrants(t *testing.T) {
	setup()

	user1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
		ResourceId:   "userA",
	})
	if err != nil {
		t.Fatal(err)
	}
	user2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
		ResourceId:   "userB",
	})
	if err != nil {
		t.Fatal(err)
	}
	newPermission, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "perm1",
		Meta: map[string]interface{}{
			"name":        "Permission 1",
			"description": "Permission 1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	userHasPermission, err := Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: newPermission.ResourceType,
				ResourceId:   newPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: user1.ResourceType,
					ResourceId:   user1.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, userHasPermission.Authorized())

	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: newPermission.ResourceType,
		ResourceId:   newPermission.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: user1.ResourceType,
			ResourceId:   user1.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: newPermission.ResourceType,
		ResourceId:   newPermission.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: user2.ResourceType,
			ResourceId:   user2.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrants1, err := ListWarrants(context.Background(), ListWarrantsOpts{
		Limit:        1,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, warrants1.Data, 1)
	require.Equal(t, newPermission.ResourceType, warrants1.Data[0].ResourceType)
	require.Equal(t, newPermission.ResourceId, warrants1.Data[0].ResourceId)
	require.Equal(t, "member", warrants1.Data[0].Relation)
	require.Equal(t, user2.ResourceType, warrants1.Data[0].Subject.ResourceType)
	require.Equal(t, user2.ResourceId, warrants1.Data[0].Subject.ResourceId)

	warrants2, err := ListWarrants(context.Background(), ListWarrantsOpts{
		Limit:        1,
		After:        warrants1.ListMetadata.After,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, warrants2.Data, 1)
	require.Equal(t, newPermission.ResourceType, warrants2.Data[0].ResourceType)
	require.Equal(t, newPermission.ResourceId, warrants2.Data[0].ResourceId)
	require.Equal(t, "member", warrants2.Data[0].Relation)
	require.Equal(t, user1.ResourceType, warrants2.Data[0].Subject.ResourceType)
	require.Equal(t, user1.ResourceId, warrants2.Data[0].Subject.ResourceId)

	warrants3, err := ListWarrants(context.Background(), ListWarrantsOpts{
		SubjectType:  "user",
		SubjectId:    user1.ResourceId,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, warrants3.Data, 1)
	require.Equal(t, newPermission.ResourceType, warrants3.Data[0].ResourceType)
	require.Equal(t, newPermission.ResourceId, warrants3.Data[0].ResourceId)
	require.Equal(t, "member", warrants3.Data[0].Relation)
	require.Equal(t, user1.ResourceType, warrants3.Data[0].Subject.ResourceType)
	require.Equal(t, user1.ResourceId, warrants3.Data[0].Subject.ResourceId)

	userHasPermission, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: newPermission.ResourceType,
				ResourceId:   newPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: user1.ResourceType,
					ResourceId:   user1.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, userHasPermission.Authorized())

	queryResponse, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", user1.ResourceId),
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, queryResponse.Data, 1)
	require.Equal(t, newPermission.ResourceType, queryResponse.Data[0].ResourceType)
	require.Equal(t, newPermission.ResourceId, queryResponse.Data[0].ResourceId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: newPermission.ResourceType,
		ResourceId:   newPermission.ResourceId,
		Relation:     "member",
		Subject: Subject{
			ResourceType: user1.ResourceType,
			ResourceId:   user1.ResourceId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	userHasPermission, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: newPermission.ResourceType,
				ResourceId:   newPermission.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: user1.ResourceType,
					ResourceId:   user1.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, userHasPermission.Authorized())

	// Clean up
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: user1.ResourceType,
		ResourceId:   user1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: user2.ResourceType,
		ResourceId:   user2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: newPermission.ResourceType,
		ResourceId:   newPermission.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBatchWarrants(t *testing.T) {
	setup()

	newUser, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	permission1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "perm1",
		Meta: map[string]interface{}{
			"name":        "Permission 1",
			"description": "Permission 1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	permission2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "perm2",
		Meta: map[string]interface{}{
			"name":        "Permission 2",
			"description": "Permission 2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	userHasPermissions, err := CheckBatch(context.Background(), CheckBatchOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: permission1.ResourceType,
				ResourceId:   permission1.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: newUser.ResourceType,
					ResourceId:   newUser.ResourceId,
				},
			},
			{
				ResourceType: permission2.ResourceType,
				ResourceId:   permission2.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: newUser.ResourceType,
					ResourceId:   newUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, userHasPermissions, 2)
	require.False(t, userHasPermissions[0].Authorized())
	require.False(t, userHasPermissions[1].Authorized())

	warrantResponse, err := BatchWriteWarrants(context.Background(), []WriteWarrantOpts{
		{
			ResourceType: permission1.ResourceType,
			ResourceId:   permission1.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: newUser.ResourceType,
				ResourceId:   newUser.ResourceId,
			},
		},
		{
			Op:           "create",
			ResourceType: permission2.ResourceType,
			ResourceId:   permission2.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: newUser.ResourceType,
				ResourceId:   newUser.ResourceId,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	userHasPermissions, err = CheckBatch(context.Background(), CheckBatchOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: permission1.ResourceType,
				ResourceId:   permission1.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: newUser.ResourceType,
					ResourceId:   newUser.ResourceId,
				},
			},
			{
				ResourceType: permission2.ResourceType,
				ResourceId:   permission2.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: newUser.ResourceType,
					ResourceId:   newUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, userHasPermissions, 2)
	require.True(t, userHasPermissions[0].Authorized())
	require.True(t, userHasPermissions[1].Authorized())

	warrantResponse, err = BatchWriteWarrants(context.Background(), []WriteWarrantOpts{
		{
			Op:           "delete",
			ResourceType: permission1.ResourceType,
			ResourceId:   permission1.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: newUser.ResourceType,
				ResourceId:   newUser.ResourceId,
			},
		},
		{
			Op:           "delete",
			ResourceType: permission2.ResourceType,
			ResourceId:   permission2.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: newUser.ResourceType,
				ResourceId:   newUser.ResourceId,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	userHasPermissions, err = CheckBatch(context.Background(), CheckBatchOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: permission1.ResourceType,
				ResourceId:   permission1.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: newUser.ResourceType,
					ResourceId:   newUser.ResourceId,
				},
			},
			{
				ResourceType: permission2.ResourceType,
				ResourceId:   permission2.ResourceId,
				Relation:     "member",
				Subject: Subject{
					ResourceType: newUser.ResourceType,
					ResourceId:   newUser.ResourceId,
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, userHasPermissions, 2)
	require.False(t, userHasPermissions[0].Authorized())
	require.False(t, userHasPermissions[1].Authorized())

	// Clean up
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: newUser.ResourceType,
		ResourceId:   newUser.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: permission1.ResourceType,
		ResourceId:   permission1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: permission2.ResourceType,
		ResourceId:   permission2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWarrantsWithPolicy(t *testing.T) {
	setup()

	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ResourceType: "permission",
		ResourceId:   "test-permission",
		Relation:     "member",
		Subject: Subject{
			ResourceType: "user",
			ResourceId:   "user-1",
		},
		Policy: `geo == "us"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	checkResult, err := Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: "permission",
				ResourceId:   "test-permission",
				Relation:     "member",
				Subject: Subject{
					ResourceType: "user",
					ResourceId:   "user-1",
				},
				Context: map[string]interface{}{
					"geo": "us",
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, checkResult.Authorized())

	checkResult, err = Check(context.Background(), CheckOpts{
		Checks: []WarrantCheck{
			{
				ResourceType: "permission",
				ResourceId:   "test-permission",
				Relation:     "member",
				Subject: Subject{
					ResourceType: "user",
					ResourceId:   "user-1",
				},
				Context: map[string]interface{}{
					"geo": "eu",
				},
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, checkResult.Authorized())

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:           "delete",
		ResourceType: "permission",
		ResourceId:   "test-permission",
		Relation:     "member",
		Subject: Subject{
			ResourceType: "user",
			ResourceId:   "user-1",
		},
		Policy: `geo == "us"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	// Clean up
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: "permission",
		ResourceId:   "test-permission",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: "user",
		ResourceId:   "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestQueryWarrants(t *testing.T) {
	setup()

	userA, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
		ResourceId:   "userA",
	})
	if err != nil {
		t.Fatal(err)
	}
	userB, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "user",
		ResourceId:   "userB",
	})
	if err != nil {
		t.Fatal(err)
	}
	permission1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "perm1",
		Meta: map[string]interface{}{
			"name":        "Permission 1",
			"description": "This is permission 1.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	permission2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "perm2",
	})
	if err != nil {
		t.Fatal(err)
	}
	permission3, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "permission",
		ResourceId:   "perm3",
		Meta: map[string]interface{}{
			"name":        "Permission 3",
			"description": "This is permission 3.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	role1, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "role",
		ResourceId:   "role1",
		Meta: map[string]interface{}{
			"name":        "Role 1",
			"description": "This is role 1.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	role2, err := CreateResource(context.Background(), CreateResourceOpts{
		ResourceType: "role",
		ResourceId:   "role2",
		Meta: map[string]interface{}{
			"name": "Role 2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	warrantResponse, err := BatchWriteWarrants(context.Background(), []WriteWarrantOpts{
		{
			ResourceType: permission1.ResourceType,
			ResourceId:   permission1.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: role1.ResourceType,
				ResourceId:   role1.ResourceId,
			},
		},
		{
			ResourceType: permission2.ResourceType,
			ResourceId:   permission2.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: role2.ResourceType,
				ResourceId:   role2.ResourceId,
			},
		},
		{
			ResourceType: permission3.ResourceType,
			ResourceId:   permission3.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: role2.ResourceType,
				ResourceId:   role2.ResourceId,
			},
		},
		{
			ResourceType: role2.ResourceType,
			ResourceId:   role2.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: role1.ResourceType,
				ResourceId:   role1.ResourceId,
			},
		},
		{
			ResourceType: permission1.ResourceType,
			ResourceId:   permission1.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: role2.ResourceType,
				ResourceId:   role2.ResourceId,
			},
			Policy: "tenantId == 123",
		},
		{
			ResourceType: role1.ResourceType,
			ResourceId:   role1.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: userA.ResourceType,
				ResourceId:   userA.ResourceId,
			},
		},
		{
			ResourceType: role2.ResourceType,
			ResourceId:   role2.ResourceId,
			Relation:     "member",
			Subject: Subject{
				ResourceType: userB.ResourceType,
				ResourceId:   userB.ResourceId,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	queryResponse, err := Query(context.Background(), QueryOpts{
		Query:        "select role where user:userA is member",
		Limit:        1,
		Order:        Asc,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, queryResponse.Data, 1)
	require.Equal(t, role1.ResourceType, queryResponse.Data[0].ResourceType)
	require.Equal(t, role1.ResourceId, queryResponse.Data[0].ResourceId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)
	require.Equal(t, role1.ResourceType, queryResponse.Data[0].Warrant.ResourceType)
	require.Equal(t, role1.ResourceId, queryResponse.Data[0].Warrant.ResourceId)
	require.Equal(t, "member", queryResponse.Data[0].Warrant.Relation)
	require.Equal(t, userA.ResourceType, queryResponse.Data[0].Warrant.Subject.ResourceType)
	require.Equal(t, userA.ResourceId, queryResponse.Data[0].Warrant.Subject.ResourceId)
	require.Empty(t, queryResponse.Data[0].Warrant.Policy)
	require.False(t, queryResponse.Data[0].IsImplicit)

	queryResponse, err = Query(context.Background(), QueryOpts{
		Query:        "select role where user:userA is member",
		Limit:        1,
		Order:        Asc,
		After:        queryResponse.ListMetadata.After,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, queryResponse.Data, 1)
	require.Equal(t, role2.ResourceType, queryResponse.Data[0].ResourceType)
	require.Equal(t, role2.ResourceId, queryResponse.Data[0].ResourceId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)
	require.Equal(t, role2.ResourceType, queryResponse.Data[0].Warrant.ResourceType)
	require.Equal(t, role2.ResourceId, queryResponse.Data[0].Warrant.ResourceId)
	require.Equal(t, "member", queryResponse.Data[0].Warrant.Relation)
	require.Equal(t, role1.ResourceType, queryResponse.Data[0].Warrant.Subject.ResourceType)
	require.Equal(t, role1.ResourceId, queryResponse.Data[0].Warrant.Subject.ResourceId)
	require.Empty(t, queryResponse.Data[0].Warrant.Policy)
	require.True(t, queryResponse.Data[0].IsImplicit)

	queryResponse, err = Query(context.Background(), QueryOpts{
		Query: "select permission where user:userB is member",
		Context: Context{
			"tenantId": 123,
		},
		Order:        Asc,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, queryResponse.Data, 3)
	require.Equal(t, permission1.ResourceType, queryResponse.Data[0].ResourceType)
	require.Equal(t, permission1.ResourceId, queryResponse.Data[0].ResourceId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)
	require.Equal(t, permission2.ResourceType, queryResponse.Data[1].ResourceType)
	require.Equal(t, permission2.ResourceId, queryResponse.Data[1].ResourceId)
	require.Equal(t, "member", queryResponse.Data[1].Relation)
	require.Equal(t, permission3.ResourceType, queryResponse.Data[2].ResourceType)
	require.Equal(t, permission3.ResourceId, queryResponse.Data[2].ResourceId)
	require.Equal(t, "member", queryResponse.Data[2].Relation)

	// Clean up
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: role1.ResourceType,
		ResourceId:   role1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: role2.ResourceType,
		ResourceId:   role2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: permission1.ResourceType,
		ResourceId:   permission1.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: permission2.ResourceType,
		ResourceId:   permission2.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: permission3.ResourceType,
		ResourceId:   permission3.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: userA.ResourceType,
		ResourceId:   userA.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteResource(context.Background(), DeleteResourceOpts{
		ResourceType: userB.ResourceType,
		ResourceId:   userB.ResourceId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConvertSchemaLive(t *testing.T) {
	setup()
	schema := "version 0.1\n\ntype report\n    relation owner []\n    relation editor []\n    relation viewer []\n    \n    inherit editor if\n        relation owner\n        \n    inherit viewer if\n        relation editor"

	response, err := ConvertSchemaToResourceTypes(context.Background(), ConvertSchemaToResourceTypesOpts{
		Schema: schema,
	})
	if err != nil {
		t.Fatal(err)
	}

	require.Len(t, response.ResourceTypes, 1)
	require.Equal(t, response.Version, "0.1")
	require.Equal(t, response, ConvertSchemaResponse{
		Version: "0.1",
		ResourceTypes: []ResourceType{
			{
				Type: "report",
				Relations: map[string]interface{}{
					"owner": map[string]interface{}{},
					"editor": map[string]interface{}{
						"inherit_if": "owner",
					},
					"viewer": map[string]interface{}{
						"inherit_if": "editor",
					},
				},
			},
		},
	})
}

func TestConvertResourceTypesLive(t *testing.T) {
	setup()

	response, err := ConvertResourceTypesToSchema(context.Background(), ConvertResourceTypesToSchemaOpts{
		Version: "0.1",
		ResourceTypes: []ResourceType{
			{
				Type: "report",
				Relations: map[string]interface{}{
					"owner": map[string]interface{}{},
					"editor": map[string]interface{}{
						"inherit_if": "owner",
					},
					"viewer": map[string]interface{}{
						"inherit_if": "editor",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, response.Version, "0.1")
	require.NotNil(t, response.Schema)

	resourceTypeResponse, err := ConvertSchemaToResourceTypes(context.Background(), ConvertSchemaToResourceTypesOpts{
		Schema: *response.Schema,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, resourceTypeResponse, ConvertSchemaResponse{
		Version: "0.1",
		ResourceTypes: []ResourceType{
			{
				Type: "report",
				Relations: map[string]interface{}{
					"owner": map[string]interface{}{},
					"editor": map[string]interface{}{
						"inherit_if": "owner",
					},
					"viewer": map[string]interface{}{
						"inherit_if": "editor",
					},
				},
			},
		},
	})
}
