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

func TestCrudObjects(t *testing.T) {
	setup()

	object1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "document",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "document", object1.ObjectType)
	require.NotEmpty(t, object1.ObjectId)
	require.Empty(t, object1.Meta)

	object2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "folder",
		ObjectId:   "planning",
	})
	if err != nil {
		t.Fatal(err)
	}
	refetchedObject, err := GetObject(context.Background(), GetObjectOpts{
		ObjectType: object2.ObjectType,
		ObjectId:   object2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, object2.ObjectType, refetchedObject.ObjectType)
	require.Equal(t, object2.ObjectId, refetchedObject.ObjectId)
	require.EqualValues(t, object2.Meta, refetchedObject.Meta)

	object2, err = UpdateObject(context.Background(), UpdateObjectOpts{
		ObjectType: object2.ObjectType,
		ObjectId:   object2.ObjectId,
		Meta: map[string]interface{}{
			"description": "Folder object",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	refetchedObject, err = GetObject(context.Background(), GetObjectOpts{
		ObjectType: object2.ObjectType,
		ObjectId:   object2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, object2.ObjectType, refetchedObject.ObjectType)
	require.Equal(t, object2.ObjectId, refetchedObject.ObjectId)
	require.EqualValues(t, object2.Meta, refetchedObject.Meta)

	objectsList, err := ListObjects(context.Background(), ListObjectsOpts{
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, objectsList.Data, 2)
	require.Equal(t, object2.ObjectType, objectsList.Data[0].ObjectType)
	require.Equal(t, object2.ObjectId, objectsList.Data[0].ObjectId)
	require.Equal(t, object1.ObjectType, objectsList.Data[1].ObjectType)
	require.Equal(t, object1.ObjectId, objectsList.Data[1].ObjectId)

	// Sort in ascending order
	objectsList, err = ListObjects(context.Background(), ListObjectsOpts{
		Limit: 10,
		Order: Asc,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, objectsList.Data, 2)
	require.Equal(t, object1.ObjectType, objectsList.Data[0].ObjectType)
	require.Equal(t, object1.ObjectId, objectsList.Data[0].ObjectId)
	require.Equal(t, object2.ObjectType, objectsList.Data[1].ObjectType)
	require.Equal(t, object2.ObjectId, objectsList.Data[1].ObjectId)

	objectsList, err = ListObjects(context.Background(), ListObjectsOpts{
		Limit:  10,
		Search: "planning",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, objectsList.Data, 1)
	require.Equal(t, object2.ObjectType, objectsList.Data[0].ObjectType)
	require.Equal(t, object2.ObjectId, objectsList.Data[0].ObjectId)

	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: object1.ObjectType,
		ObjectId:   object1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: object2.ObjectType,
		ObjectId:   object2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	objectsList, err = ListObjects(context.Background(), ListObjectsOpts{
		Limit:  10,
		Search: "planning",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, objectsList.Data, 0)
}

func TestMultiTenancy(t *testing.T) {
	setup()

	// Create users
	user1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	user2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create tenants
	tenant1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "tenant",
		ObjectId:   "tenant-1",
		Meta: map[string]interface{}{
			"name": "Tenant 1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tenant2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "tenant",
		ObjectId:   "tenant-2",
		Meta: map[string]interface{}{
			"name": "Tenant 2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	user1TenantsList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select tenant where user:%s is member", user1.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, user1TenantsList.Data, 0)
	tenant1UsersList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select member of type user for tenant:%s", tenant1.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, tenant1UsersList.Data, 0)

	// Assign user1 -> tenant1
	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: tenant1.ObjectType,
		ObjectId:   tenant1.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: user1.ObjectType,
			ObjectId:   user1.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	user1TenantsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select tenant where user:%s is member", user1.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, user1TenantsList.Data, 1)
	require.Equal(t, "tenant", user1TenantsList.Data[0].ObjectType)
	require.Equal(t, "tenant-1", user1TenantsList.Data[0].ObjectId)
	require.EqualValues(t, map[string]interface{}{
		"name": "Tenant 1",
	}, user1TenantsList.Data[0].Meta)

	tenant1UsersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select member of type user for tenant:%s", tenant1.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, tenant1UsersList.Data, 1)
	require.Equal(t, "user", tenant1UsersList.Data[0].ObjectType)
	require.Equal(t, user1.ObjectId, tenant1UsersList.Data[0].ObjectId)
	require.Empty(t, tenant1UsersList.Data[0].Meta)

	// Remove user1 -> tenant1
	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: tenant1.ObjectType,
		ObjectId:   tenant1.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: user1.ObjectType,
			ObjectId:   user1.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	user1TenantsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select tenant where user:%s is member", user1.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, user1TenantsList.Data, 0)
	tenant1UsersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select member of type user for tenant:%s", tenant1.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, tenant1UsersList.Data, 0)

	// Clean up
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: user1.ObjectType,
		ObjectId:   user1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: user2.ObjectType,
		ObjectId:   user2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: tenant1.ObjectType,
		ObjectId:   tenant1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: tenant2.ObjectType,
		ObjectId:   tenant2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRBAC(t *testing.T) {
	setup()

	// Create users
	adminUser, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	viewerUser, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create roles
	adminRole, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "role",
		ObjectId:   "administrator",
		Meta: map[string]interface{}{
			"name":        "Administrator",
			"description": "The admin role",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	viewerRole, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "role",
		ObjectId:   "viewer",
		Meta: map[string]interface{}{
			"name":        "Viewer",
			"description": "The viewer role",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create permissions
	createPermission, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "create-report",
		Meta: map[string]interface{}{
			"name":        "Create Report",
			"description": "Permission to create reports",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	viewPermission, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "view-report",
		Meta: map[string]interface{}{
			"name":        "View Report",
			"description": "Permission to view reports",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	adminUserRolesList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select role where user:%s is member", adminUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminUserRolesList.Data, 0)

	adminRolePermissionsList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where role:%s is member", adminRole.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminRolePermissionsList.Data, 0)

	adminUserHasPermission, err := Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: createPermission.ObjectType,
			ObjectId:   createPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: adminUser.ObjectType,
				ObjectId:   adminUser.ObjectId,
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
		ObjectType: createPermission.ObjectType,
		ObjectId:   createPermission.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: adminRole.ObjectType,
			ObjectId:   adminRole.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: adminRole.ObjectType,
		ObjectId:   adminRole.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: adminUser.ObjectType,
			ObjectId:   adminUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	adminUserHasPermission, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: createPermission.ObjectType,
			ObjectId:   createPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: adminUser.ObjectType,
				ObjectId:   adminUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, adminUserHasPermission.Authorized())

	adminUserRolesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select role where user:%s is member", adminUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminUserRolesList.Data, 1)
	require.Equal(t, "role", adminUserRolesList.Data[0].ObjectType)
	require.Equal(t, adminRole.ObjectId, adminUserRolesList.Data[0].ObjectId)
	require.Equal(t, map[string]interface{}{
		"name":        "Administrator",
		"description": "The admin role",
	}, adminUserRolesList.Data[0].Meta)

	adminRolePermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where role:%s is member", adminRole.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminRolePermissionsList.Data, 1)
	require.Equal(t, "permission", adminRolePermissionsList.Data[0].ObjectType)
	require.Equal(t, createPermission.ObjectId, adminRolePermissionsList.Data[0].ObjectId)
	require.Equal(t, map[string]interface{}{
		"name":        "Create Report",
		"description": "Permission to create reports",
	}, adminRolePermissionsList.Data[0].Meta)

	// Remove create-report permission -> admin role -> admin user
	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: createPermission.ObjectType,
		ObjectId:   createPermission.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: adminRole.ObjectType,
			ObjectId:   adminRole.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: adminRole.ObjectType,
		ObjectId:   adminRole.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: adminUser.ObjectType,
			ObjectId:   adminUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	adminUserHasPermission, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: createPermission.ObjectType,
			ObjectId:   createPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: adminUser.ObjectType,
				ObjectId:   adminUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, adminUserHasPermission.Authorized())

	adminUserRolesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select role where user:%s is member", adminUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminUserRolesList.Data, 0)

	adminRolePermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where role:%s is member", adminRole.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, adminRolePermissionsList.Data, 0)

	// Assign view-report -> viewer user
	viewerUserHasPermission, err := Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: viewPermission.ObjectType,
			ObjectId:   viewPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: viewerUser.ObjectType,
				ObjectId:   viewerUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, viewerUserHasPermission.Authorized())

	viewerUserPermissionsList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", viewerUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, viewerUserPermissionsList.Data)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: viewPermission.ObjectType,
		ObjectId:   viewPermission.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: viewerUser.ObjectType,
			ObjectId:   viewerUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	viewerUserHasPermission, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: viewPermission.ObjectType,
			ObjectId:   viewPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: viewerUser.ObjectType,
				ObjectId:   viewerUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, viewerUserHasPermission.Authorized())

	viewerUserPermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", viewerUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, viewerUserPermissionsList.Data, 1)
	require.Equal(t, "permission", viewerUserPermissionsList.Data[0].ObjectType)
	require.Equal(t, viewPermission.ObjectId, viewerUserPermissionsList.Data[0].ObjectId)
	require.Equal(t, map[string]interface{}{
		"name":        "View Report",
		"description": "Permission to view reports",
	}, viewerUserPermissionsList.Data[0].Meta)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: viewPermission.ObjectType,
		ObjectId:   viewPermission.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: viewerUser.ObjectType,
			ObjectId:   viewerUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	viewerUserHasPermission, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: viewPermission.ObjectType,
			ObjectId:   viewPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: viewerUser.ObjectType,
				ObjectId:   viewerUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, viewerUserHasPermission.Authorized())

	viewerUserPermissionsList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", viewerUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, viewerUserPermissionsList.Data)

	// Clean up
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: adminUser.ObjectType,
		ObjectId:   adminUser.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: viewerUser.ObjectType,
		ObjectId:   viewerUser.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: adminRole.ObjectType,
		ObjectId:   adminRole.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: viewerRole.ObjectType,
		ObjectId:   viewerRole.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: createPermission.ObjectType,
		ObjectId:   createPermission.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: viewPermission.ObjectType,
		ObjectId:   viewPermission.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPricingTiersFeaturesAndUsers(t *testing.T) {
	setup()

	// Create users
	freeUser, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	paidUser, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create pricing tiers
	freeTier, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "pricing-tier",
		ObjectId:   "free",
		Meta: map[string]interface{}{
			"name": "Free Tier",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	paidTier, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "pricing-tier",
		ObjectId:   "paid",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create features
	customFeature, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "feature",
		ObjectId:   "custom",
		Meta: map[string]interface{}{
			"name": "Custom Feature",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	feature1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "feature",
		ObjectId:   "feature-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	feature2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "feature",
		ObjectId:   "feature-2",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Assign custom-feature -> paid user
	paidUserHasFeature, err := Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: customFeature.ObjectType,
			ObjectId:   customFeature.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: paidUser.ObjectType,
				ObjectId:   paidUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, paidUserHasFeature.Authorized())

	paidUserFeaturesList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", paidUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, paidUserFeaturesList.Data)

	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: customFeature.ObjectType,
		ObjectId:   customFeature.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: paidUser.ObjectType,
			ObjectId:   paidUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	paidUserHasFeature, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: customFeature.ObjectType,
			ObjectId:   customFeature.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: paidUser.ObjectType,
				ObjectId:   paidUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, paidUserHasFeature.Authorized())

	paidUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", paidUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, paidUserFeaturesList.Data, 1)
	require.Equal(t, "feature", paidUserFeaturesList.Data[0].ObjectType)
	require.Equal(t, customFeature.ObjectId, paidUserFeaturesList.Data[0].ObjectId)
	require.Equal(t, map[string]interface{}{
		"name": "Custom Feature",
	}, paidUserFeaturesList.Data[0].Meta)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: customFeature.ObjectType,
		ObjectId:   customFeature.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: paidUser.ObjectType,
			ObjectId:   paidUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	paidUserHasFeature, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: customFeature.ObjectType,
			ObjectId:   customFeature.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: paidUser.ObjectType,
				ObjectId:   paidUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, paidUserHasFeature.Authorized())

	paidUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", paidUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, paidUserFeaturesList.Data)

	// Assign feature-1 -> free tier -> free user
	freeUserHasFeature, err := Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: feature1.ObjectType,
			ObjectId:   feature1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: freeUser.ObjectType,
				ObjectId:   freeUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, freeUserHasFeature.Authorized())

	freeUserFeaturesList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", freeUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, freeUserFeaturesList.Data)

	featureUserTiersList, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select pricing-tier where user:%s is member", freeUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, featureUserTiersList.Data)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: feature1.ObjectType,
		ObjectId:   feature1.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: freeTier.ObjectType,
			ObjectId:   freeTier.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: freeTier.ObjectType,
		ObjectId:   freeTier.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: freeUser.ObjectType,
			ObjectId:   freeUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	freeUserHasFeature, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: feature1.ObjectType,
			ObjectId:   feature1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: freeUser.ObjectType,
				ObjectId:   freeUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, freeUserHasFeature.Authorized())

	freeUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", freeUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, freeUserFeaturesList.Data, 1)
	require.Equal(t, "feature", freeUserFeaturesList.Data[0].ObjectType)
	require.Equal(t, feature1.ObjectId, freeUserFeaturesList.Data[0].ObjectId)
	require.Empty(t, freeUserFeaturesList.Data[0].Meta)

	featureUserTiersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select pricing-tier where user:%s is member", freeUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, featureUserTiersList.Data, 1)
	require.Equal(t, "pricing-tier", featureUserTiersList.Data[0].ObjectType)
	require.Equal(t, freeTier.ObjectId, featureUserTiersList.Data[0].ObjectId)
	require.Equal(t, map[string]interface{}{
		"name": "Free Tier",
	}, featureUserTiersList.Data[0].Meta)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: feature1.ObjectType,
		ObjectId:   feature1.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: freeTier.ObjectType,
			ObjectId:   freeTier.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: freeTier.ObjectType,
		ObjectId:   freeTier.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: freeUser.ObjectType,
			ObjectId:   freeUser.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	freeUserHasFeature, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: feature1.ObjectType,
			ObjectId:   feature1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: freeUser.ObjectType,
				ObjectId:   freeUser.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, freeUserHasFeature.Authorized())

	freeUserFeaturesList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select feature where user:%s is member", freeUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, freeUserFeaturesList.Data)

	featureUserTiersList, err = Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select pricing-tier where user:%s is member", freeUser.ObjectId),
		Limit:        10,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Empty(t, featureUserTiersList.Data)

	// Clean up
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: freeUser.ObjectType,
		ObjectId:   freeUser.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: paidUser.ObjectType,
		ObjectId:   paidUser.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: freeTier.ObjectType,
		ObjectId:   freeTier.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: paidTier.ObjectType,
		ObjectId:   paidTier.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: customFeature.ObjectType,
		ObjectId:   customFeature.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: feature1.ObjectType,
		ObjectId:   feature1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: feature2.ObjectType,
		ObjectId:   feature2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWarrants(t *testing.T) {
	setup()

	user1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
		ObjectId:   "userA",
	})
	if err != nil {
		t.Fatal(err)
	}
	user2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
		ObjectId:   "userB",
	})
	if err != nil {
		t.Fatal(err)
	}
	newPermission, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "perm1",
		Meta: map[string]interface{}{
			"name":        "Permission 1",
			"description": "Permission 1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	userHasPermission, err := Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: newPermission.ObjectType,
			ObjectId:   newPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: user1.ObjectType,
				ObjectId:   user1.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, userHasPermission.Authorized())

	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: newPermission.ObjectType,
		ObjectId:   newPermission.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: user1.ObjectType,
			ObjectId:   user1.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: newPermission.ObjectType,
		ObjectId:   newPermission.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: user2.ObjectType,
			ObjectId:   user2.ObjectId,
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
	require.Equal(t, newPermission.ObjectType, warrants1.Data[0].ObjectType)
	require.Equal(t, newPermission.ObjectId, warrants1.Data[0].ObjectId)
	require.Equal(t, "member", warrants1.Data[0].Relation)
	require.Equal(t, user2.ObjectType, warrants1.Data[0].Subject.ObjectType)
	require.Equal(t, user2.ObjectId, warrants1.Data[0].Subject.ObjectId)

	warrants2, err := ListWarrants(context.Background(), ListWarrantsOpts{
		Limit:        1,
		After:        warrants1.ListMetadata.After,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, warrants2.Data, 1)
	require.Equal(t, newPermission.ObjectType, warrants2.Data[0].ObjectType)
	require.Equal(t, newPermission.ObjectId, warrants2.Data[0].ObjectId)
	require.Equal(t, "member", warrants2.Data[0].Relation)
	require.Equal(t, user1.ObjectType, warrants2.Data[0].Subject.ObjectType)
	require.Equal(t, user1.ObjectId, warrants2.Data[0].Subject.ObjectId)

	warrants3, err := ListWarrants(context.Background(), ListWarrantsOpts{
		SubjectType:  "user",
		SubjectId:    user1.ObjectId,
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, warrants3.Data, 1)
	require.Equal(t, newPermission.ObjectType, warrants3.Data[0].ObjectType)
	require.Equal(t, newPermission.ObjectId, warrants3.Data[0].ObjectId)
	require.Equal(t, "member", warrants3.Data[0].Relation)
	require.Equal(t, user1.ObjectType, warrants3.Data[0].Subject.ObjectType)
	require.Equal(t, user1.ObjectId, warrants3.Data[0].Subject.ObjectId)

	userHasPermission, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: newPermission.ObjectType,
			ObjectId:   newPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: user1.ObjectType,
				ObjectId:   user1.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, userHasPermission.Authorized())

	queryResponse, err := Query(context.Background(), QueryOpts{
		Query:        fmt.Sprintf("select permission where user:%s is member", user1.ObjectId),
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Len(t, queryResponse.Data, 1)
	require.Equal(t, newPermission.ObjectType, queryResponse.Data[0].ObjectType)
	require.Equal(t, newPermission.ObjectId, queryResponse.Data[0].ObjectId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: newPermission.ObjectType,
		ObjectId:   newPermission.ObjectId,
		Relation:   "member",
		Subject: Subject{
			ObjectType: user1.ObjectType,
			ObjectId:   user1.ObjectId,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	userHasPermission, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: newPermission.ObjectType,
			ObjectId:   newPermission.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: user1.ObjectType,
				ObjectId:   user1.ObjectId,
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, userHasPermission.Authorized())

	// Clean up
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: user1.ObjectType,
		ObjectId:   user1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: user2.ObjectType,
		ObjectId:   user2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: newPermission.ObjectType,
		ObjectId:   newPermission.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBatchWarrants(t *testing.T) {
	setup()

	newUser, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	permission1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "perm1",
		Meta: map[string]interface{}{
			"name":        "Permission 1",
			"description": "Permission 1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	permission2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "perm2",
		Meta: map[string]interface{}{
			"name":        "Permission 2",
			"description": "Permission 2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	userHasPermissions, err := BatchCheck(context.Background(), BatchCheckOpts{
		Warrants: []WarrantCheck{
			{
				ObjectType: permission1.ObjectType,
				ObjectId:   permission1.ObjectId,
				Relation:   "member",
				Subject: Subject{
					ObjectType: newUser.ObjectType,
					ObjectId:   newUser.ObjectId,
				},
			},
			{
				ObjectType: permission2.ObjectType,
				ObjectId:   permission2.ObjectId,
				Relation:   "member",
				Subject: Subject{
					ObjectType: newUser.ObjectType,
					ObjectId:   newUser.ObjectId,
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
			ObjectType: permission1.ObjectType,
			ObjectId:   permission1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: newUser.ObjectType,
				ObjectId:   newUser.ObjectId,
			},
		},
		{
			Op:         "create",
			ObjectType: permission2.ObjectType,
			ObjectId:   permission2.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: newUser.ObjectType,
				ObjectId:   newUser.ObjectId,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	userHasPermissions, err = BatchCheck(context.Background(), BatchCheckOpts{
		Warrants: []WarrantCheck{
			{
				ObjectType: permission1.ObjectType,
				ObjectId:   permission1.ObjectId,
				Relation:   "member",
				Subject: Subject{
					ObjectType: newUser.ObjectType,
					ObjectId:   newUser.ObjectId,
				},
			},
			{
				ObjectType: permission2.ObjectType,
				ObjectId:   permission2.ObjectId,
				Relation:   "member",
				Subject: Subject{
					ObjectType: newUser.ObjectType,
					ObjectId:   newUser.ObjectId,
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
			Op:         "delete",
			ObjectType: permission1.ObjectType,
			ObjectId:   permission1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: newUser.ObjectType,
				ObjectId:   newUser.ObjectId,
			},
		},
		{
			Op:         "delete",
			ObjectType: permission2.ObjectType,
			ObjectId:   permission2.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: newUser.ObjectType,
				ObjectId:   newUser.ObjectId,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	userHasPermissions, err = BatchCheck(context.Background(), BatchCheckOpts{
		Warrants: []WarrantCheck{
			{
				ObjectType: permission1.ObjectType,
				ObjectId:   permission1.ObjectId,
				Relation:   "member",
				Subject: Subject{
					ObjectType: newUser.ObjectType,
					ObjectId:   newUser.ObjectId,
				},
			},
			{
				ObjectType: permission2.ObjectType,
				ObjectId:   permission2.ObjectId,
				Relation:   "member",
				Subject: Subject{
					ObjectType: newUser.ObjectType,
					ObjectId:   newUser.ObjectId,
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
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: newUser.ObjectType,
		ObjectId:   newUser.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: permission1.ObjectType,
		ObjectId:   permission1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: permission2.ObjectType,
		ObjectId:   permission2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWarrantsWithPolicy(t *testing.T) {
	setup()

	warrantResponse, err := WriteWarrant(context.Background(), WriteWarrantOpts{
		ObjectType: "permission",
		ObjectId:   "test-permission",
		Relation:   "member",
		Subject: Subject{
			ObjectType: "user",
			ObjectId:   "user-1",
		},
		Policy: `geo == "us"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	checkResult, err := Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: "permission",
			ObjectId:   "test-permission",
			Relation:   "member",
			Subject: Subject{
				ObjectType: "user",
				ObjectId:   "user-1",
			},
			Context: map[string]interface{}{
				"geo": "us",
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, checkResult.Authorized())

	checkResult, err = Check(context.Background(), CheckOpts{
		Warrant: WarrantCheck{
			ObjectType: "permission",
			ObjectId:   "test-permission",
			Relation:   "member",
			Subject: Subject{
				ObjectType: "user",
				ObjectId:   "user-1",
			},
			Context: map[string]interface{}{
				"geo": "eu",
			},
		},
		WarrantToken: "latest",
	})
	if err != nil {
		t.Fatal(err)
	}
	require.False(t, checkResult.Authorized())

	warrantResponse, err = WriteWarrant(context.Background(), WriteWarrantOpts{
		Op:         "delete",
		ObjectType: "permission",
		ObjectId:   "test-permission",
		Relation:   "member",
		Subject: Subject{
			ObjectType: "user",
			ObjectId:   "user-1",
		},
		Policy: `geo == "us"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.NotEmpty(t, warrantResponse.WarrantToken)

	// Clean up
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: "permission",
		ObjectId:   "test-permission",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: "user",
		ObjectId:   "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestQueryWarrants(t *testing.T) {
	setup()

	userA, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
		ObjectId:   "userA",
	})
	if err != nil {
		t.Fatal(err)
	}
	userB, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "user",
		ObjectId:   "userB",
	})
	if err != nil {
		t.Fatal(err)
	}
	permission1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "perm1",
		Meta: map[string]interface{}{
			"name":        "Permission 1",
			"description": "This is permission 1.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	permission2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "perm2",
	})
	if err != nil {
		t.Fatal(err)
	}
	permission3, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "permission",
		ObjectId:   "perm3",
		Meta: map[string]interface{}{
			"name":        "Permission 3",
			"description": "This is permission 3.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	role1, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "role",
		ObjectId:   "role1",
		Meta: map[string]interface{}{
			"name":        "Role 1",
			"description": "This is role 1.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	role2, err := CreateObject(context.Background(), CreateObjectOpts{
		ObjectType: "role",
		ObjectId:   "role2",
		Meta: map[string]interface{}{
			"name": "Role 2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	warrantResponse, err := BatchWriteWarrants(context.Background(), []WriteWarrantOpts{
		{
			ObjectType: permission1.ObjectType,
			ObjectId:   permission1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: role1.ObjectType,
				ObjectId:   role1.ObjectId,
			},
		},
		{
			ObjectType: permission2.ObjectType,
			ObjectId:   permission2.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: role2.ObjectType,
				ObjectId:   role2.ObjectId,
			},
		},
		{
			ObjectType: permission3.ObjectType,
			ObjectId:   permission3.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: role2.ObjectType,
				ObjectId:   role2.ObjectId,
			},
		},
		{
			ObjectType: role2.ObjectType,
			ObjectId:   role2.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: role1.ObjectType,
				ObjectId:   role1.ObjectId,
			},
		},
		{
			ObjectType: permission1.ObjectType,
			ObjectId:   permission1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: role2.ObjectType,
				ObjectId:   role2.ObjectId,
			},
			Policy: "tenantId == 123",
		},
		{
			ObjectType: role1.ObjectType,
			ObjectId:   role1.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: userA.ObjectType,
				ObjectId:   userA.ObjectId,
			},
		},
		{
			ObjectType: role2.ObjectType,
			ObjectId:   role2.ObjectId,
			Relation:   "member",
			Subject: Subject{
				ObjectType: userB.ObjectType,
				ObjectId:   userB.ObjectId,
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
	require.Equal(t, role1.ObjectType, queryResponse.Data[0].ObjectType)
	require.Equal(t, role1.ObjectId, queryResponse.Data[0].ObjectId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)
	require.Equal(t, role1.ObjectType, queryResponse.Data[0].Warrant.ObjectType)
	require.Equal(t, role1.ObjectId, queryResponse.Data[0].Warrant.ObjectId)
	require.Equal(t, "member", queryResponse.Data[0].Warrant.Relation)
	require.Equal(t, userA.ObjectType, queryResponse.Data[0].Warrant.Subject.ObjectType)
	require.Equal(t, userA.ObjectId, queryResponse.Data[0].Warrant.Subject.ObjectId)
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
	require.Equal(t, role2.ObjectType, queryResponse.Data[0].ObjectType)
	require.Equal(t, role2.ObjectId, queryResponse.Data[0].ObjectId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)
	require.Equal(t, role2.ObjectType, queryResponse.Data[0].Warrant.ObjectType)
	require.Equal(t, role2.ObjectId, queryResponse.Data[0].Warrant.ObjectId)
	require.Equal(t, "member", queryResponse.Data[0].Warrant.Relation)
	require.Equal(t, role1.ObjectType, queryResponse.Data[0].Warrant.Subject.ObjectType)
	require.Equal(t, role1.ObjectId, queryResponse.Data[0].Warrant.Subject.ObjectId)
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
	require.Equal(t, permission1.ObjectType, queryResponse.Data[0].ObjectType)
	require.Equal(t, permission1.ObjectId, queryResponse.Data[0].ObjectId)
	require.Equal(t, "member", queryResponse.Data[0].Relation)
	require.Equal(t, permission2.ObjectType, queryResponse.Data[1].ObjectType)
	require.Equal(t, permission2.ObjectId, queryResponse.Data[1].ObjectId)
	require.Equal(t, "member", queryResponse.Data[1].Relation)
	require.Equal(t, permission3.ObjectType, queryResponse.Data[2].ObjectType)
	require.Equal(t, permission3.ObjectId, queryResponse.Data[2].ObjectId)
	require.Equal(t, "member", queryResponse.Data[2].Relation)

	// Clean up
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: role1.ObjectType,
		ObjectId:   role1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: role2.ObjectType,
		ObjectId:   role2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: permission1.ObjectType,
		ObjectId:   permission1.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: permission2.ObjectType,
		ObjectId:   permission2.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: permission3.ObjectType,
		ObjectId:   permission3.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: userA.ObjectType,
		ObjectId:   userA.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = DeleteObject(context.Background(), DeleteObjectOpts{
		ObjectType: userB.ObjectType,
		ObjectId:   userB.ObjectId,
	})
	if err != nil {
		t.Fatal(err)
	}
}
