# Changelog

## [9.3.0](https://github.com/workos/workos-go/compare/v9.2.0...v9.3.0) (2026-06-18)

- [#566](https://github.com/workos/workos-go/pull/566) feat(generated)!: regenerate from spec (11 changes)

  **⚠️ Breaking**
  - **[organization_membership](https://workos.com/docs/reference/authkit/organization-membership)**:
    - Changed response of `UserManagementOrganizationMembership.list` from `UserOrganizationMembership` to `UserOrganizationMembershipList`
  - **[pipes](https://workos.com/docs/reference/pipes)**:
    - SDK surface change: `PipeService.CreateDataIntegrationToken` was renamed to `PipeService.GetAccessToken`
  - **[user_management](https://workos.com/docs/reference/authkit/user)**:
    - Changed response of `UserManagementInvitations.list` from `UserInvite` to `UserInviteList`

  **Features**
  - **[authorization](https://workos.com/docs/reference/fga)**:
    - Added model `ReplaceGroupRoleAssignmentEntry`
    - Added model `ReplaceGroupRoleAssignments`
    - Added model `DeleteGroupRoleAssignmentsByCriteria`
    - Added endpoint `POST /authorization/groups/{group_id}/role_assignments`
    - Added endpoint `PUT /authorization/groups/{group_id}/role_assignments`
    - Added endpoint `DELETE /authorization/groups/{group_id}/role_assignments`
    - Added endpoint `GET /authorization/groups/{group_id}/role_assignments/{role_assignment_id}`
    - Added endpoint `DELETE /authorization/groups/{group_id}/role_assignments/{role_assignment_id}`
  - **[client](https://workos.com/docs/reference)**:
    - Added model `ClientApiToken`
    - Added model `ClientApiTokenResponse`
    - Added service `Client`
  - **[connect](https://workos.com/docs/reference/workos-connect/standalone)**:
    - Added `auth_method` to `ConnectedAccount`
    - Added `api_key_last_4` to `ConnectedAccount`
    - Added enum `ConnectedAccountAuthMethod`
  - **[groups](https://workos.com/docs/reference/groups)**:
    - Added model `CreateGroupRoleAssignment`
    - Added model `GroupRoleAssignment`
    - Added model `GroupRoleAssignmentList`
    - Added model `GroupRoleAssignmentResource`
  - **[organization_membership](https://workos.com/docs/reference/authkit/organization-membership)**:
    - Added model `UserOrganizationMembershipList`
    - Added model `UserOrganizationMembershipListListMetadata`
  - **[pipes](https://workos.com/docs/reference/pipes)**:
    - Added model `DataIntegrationCredentials`
    - Added model `DataIntegrationConfigurationResponse`
    - Added model `DataIntegrationConfigurationListResponse`
    - Added model `ConfigureDataIntegrationBody`
    - Added `auth_methods` to `DataIntegrationsListResponseData`
    - Added `auth_method` to `DataIntegrationsListResponseDataConnectedAccount`
    - Added `api_key_last_4` to `DataIntegrationsListResponseDataConnectedAccount`
    - Added enum `DataIntegrationCredentialsCredentialsType`
    - Added enum `DataIntegrationsListResponseDataAuthMethods`
    - Added enum `DataIntegrationsListResponseDataConnectedAccountAuthMethod`
    - Added service `PipesProvider`
  - **[user_management](https://workos.com/docs/reference/authkit/user)**:
    - Added model `UserInviteList`
    - Added model `UserInviteListListMetadata`
    - Made `AuthorizationCodeSessionAuthenticateRequest.client_secret` optional
    - Made `RefreshTokenSessionAuthenticateRequest.client_secret` optional
  - **[widgets](https://workos.com/docs/reference/widgets)**:
    - Added `widgets:pipes:manage` to `WidgetSessionTokenScopes`

## [9.2.0](https://github.com/workos/workos-go/compare/v9.1.0...v9.2.0) (2026-06-17)

### Bug Fixes

* **renovate:** explicitly enable minor and patch updates ([#556](https://github.com/workos/workos-go/issues/556)) ([8f31158](https://github.com/workos/workos-go/commit/8f31158181395c86a5805988740444e73b8fcc92))

- [#563](https://github.com/workos/workos-go/pull/563) feat(generated): regenerate from spec (5 changes)

  **⚠️ Breaking**
  - **[api_keys](https://workos.com/docs/reference/authkit/api-keys)**:
    - Made `expires_at` required in API key models
  - **[directory_sync](https://workos.com/docs/reference/directory-sync)**:
    - Removed model `DsyncDeactivated`
    - Removed model `DsyncDeactivatedData`
    - Removed model `DsyncDeactivatedDataDomain`
    - Removed enum `DsyncDeactivatedDataType`
    - Removed enum `DsyncDeactivatedDataState`
  - **[radar](https://workos.com/docs/reference/radar)**:
    - Removed `domain_sign_up_rate_limit` from `RadarStandaloneResponseControl`
  - **[user_management](https://workos.com/docs/reference/authkit/user)**:
    - Removed `return_to` from `RevokeSession`

  **Features**
  - **[api_keys](https://workos.com/docs/reference/authkit/api-keys)**:
    - Added model `ExpireApiKey`
    - Added model `ApiKeyUpdated`
    - Added model `ApiKeyUpdatedData`
    - Added model `ApiKeyUpdatedDataOwner`
    - Added model `UserApiKeyUpdatedDataOwner`
    - Added model `ApiKeyUpdatedDataPreviousAttribute`
    - Added endpoint `POST /api_keys/{id}/expire`
  - **[audit_logs](https://workos.com/docs/reference/audit-logs)**:
    - Added `Snowflake` to `AuditLogConfigurationLogStreamType`
  - **[connect](https://workos.com/docs/reference/workos-connect/standalone)**:
    - Added `name` to `UserObject`
  - **[directory_sync](https://workos.com/docs/reference/directory-sync)**:
    - Added model `DsyncTokenCreated`
    - Added model `DsyncTokenCreatedData`
    - Added model `DsyncTokenRevoked`
    - Added model `DsyncTokenRevokedData`
  - **[user_management](https://workos.com/docs/reference/authkit/user)**:
    - Added `name` to user management models
  - **[webhooks](https://workos.com/docs/reference/webhooks)**:
    - Added `api_key.updated` to `CreateWebhookEndpointEvents`
    - Added `api_key.updated` to `UpdateWebhookEndpointEvents`

## [9.1.0](https://github.com/workos/workos-go/compare/v9.0.0...v9.1.0) (2026-05-27)

### Features

* add generated events constants package ([#560](https://github.com/workos/workos-go/issues/560)) ([4a57b0d](https://github.com/workos/workos-go/commit/4a57b0de2653001bd1c7abe7c8806626cada35e8))


### Bug Fixes

* v9 module path release workflow ([#559](https://github.com/workos/workos-go/issues/559)) ([b89d38d](https://github.com/workos/workos-go/commit/b89d38d5fe3959a23a6f348424582513ca4bccbc))

* [#554](https://github.com/workos/workos-go/pull/554) feat(generated)!: regenerate from spec (11 changes)

  **⚠️ Breaking**
  * **audit_logs:** Rename audit log model types (breaking)
    * Rename `AuditLogExportJSON` to `AuditLogExport`
    * Rename `AuditLogsRetentionJSON` to `AuditLogsRetention`
    * Rename `AuditLogActionJSON` to `AuditLogAction`
    * Rename `AuditLogExportJSONState` to `AuditLogExportState`
    * Update method signatures to use new type names
  * **authorization:** Remove `Search` parameter from `AuthorizationListResourcesParams`
  * **radar:** Remove device_fingerprint and bot_score parameters
    * Remove `DeviceFingerprint` field from `RadarCreateAttemptParams`
    * Remove `BotScore` field from `RadarCreateAttemptParams`
    * Remove enum values `CREDENTIAL_STUFFING` and `IP_SIGN_UP_RATE_LIMIT` from `RadarStandaloneResponseControl`
    * Remove and update enum values in `RadarStandaloneAssessRequestAction` (keep only `SignUp` and `SignIn` with updated values)
  * **user_management:** Refactor organization membership to dedicated service
    * Move organization membership operations from `UserManagementService` to new `OrganizationMembershipService`
    * Remove `ListOrganizationMemberships`, `CreateOrganizationMembership`, `GetOrganizationMembership`, `UpdateOrganizationMembership`, `DeleteOrganizationMembership`, `DeactivateOrganizationMembership`, `ReactivateOrganizationMembership` methods from user management
    * Remove role helper types (`UserManagementRole`, `UserManagementRoleSingle`, `UserManagementRoleMultiple`) from user management (now in organization_membership)
    * Add `ExpiresAt` field to `UserManagementCreateAPIKeyParams`
    * Remove `UserManagementOrganizationMembershipGroups()` client accessor (replaced by `OrganizationMembership()`)
    * Remove `UserManagementOrganizationMembershipGroupService` type and `ListOrganizationMembershipGroups` method
  * **vault:** Rewrite vault service with breaking API changes
    * Remove `KeyContext` struct (replaced by `map[string]string`)
    * Remove `DataKeyPair` struct (replaced by `CreateDataKeyResponse`)
    * Remove `DataKey` struct (replaced by `DecryptResponse`)
    * Remove hand-written types: `VaultObject`, `VaultObjectDigest`, `VaultObjectVersion`, `VaultListObjectsParams`, `VaultListObjectsResponse`, `VaultCreateObjectParams`, `VaultUpdateObjectParams`, `VaultDecryptDataKeyParams`
    * Rename methods: `ListObjects`→`ListKv`, `CreateObject`→`CreateKv`, `ReadObject`→`GetKv`, `ReadObjectByName`→`GetName`, `UpdateObject`→`UpdateKv`, `DeleteObject`→`DeleteKv`, `ListObjectVersions`→`ListKvVersions`, `DescribeObject`→`ListKvMetadata`, `DecryptDataKey`→`CreateDecrypt`
    * Change `LocalEncrypt` signature: second param from `DataKeyPair` to `CreateDataKeyResponse`
    * Change `LocalDecrypt` signature: second param from `DataKey` to `DecryptResponse`
    * Change `Encrypt` method: `KeyContext` param type to `map[string]string`
    * Change `VaultEncryptResult.KeyContext` field type from `KeyContext` to `map[string]string`

  **Features**
  * **api_keys:** Add expires_at field to API key models
    * Add optional `expires_at` field to `APIKeysCreateOrganizationAPIKeyParams`
    * Add optional `expires_at` field to `UserManagementCreateAPIKeyParams`
    * Add optional `expires_at` field to `APIKey`, `APIKeyCreatedData`, `APIKeyRevokedData`, `OrganizationAPIKey`, `OrganizationAPIKeyWithValue`, `UserAPIKey`, and `UserAPIKeyWithValue` models
  * **authorization:** Add filter parameters to role/resource assignment list
    * Add `ResourceID`, `ResourceExternalID`, `ResourceTypeSlug` parameters to `AuthorizationListRoleAssignmentsParams`
    * Add `RoleSlug` parameter to `AuthorizationListRoleAssignmentsForResourceByExternalIDParams` and `AuthorizationListRoleAssignmentsForResourceParams`
  * **organization_membership:** Add new organization membership service
    * Add new `OrganizationMembershipService` with methods: `List`, `Create`, `Get`, `Update`, `Delete`, `Deactivate`, `Reactivate`, `ListGroups`
    * Define `OrganizationMembershipRole` interface with single and multiple variants for flexible role assignment
    * Add corresponding parameter types for all service methods
  * **vault:** Add new generated vault methods
    * Add `CreateRekey` method for re-encrypting data keys under a new context
    * Add `ListKvMetadata` method for retrieving object metadata
    * Add object CRUD operations via generated service: `CreateKv`, `GetKv`, `GetName`, `UpdateKv`, `DeleteKv`, `ListKv`, `ListKvVersions`
  * **webhooks:** Rename webhook endpoint model type
    * Rename `WebhookEndpointJSON` to `WebhookEndpoint`
    * Rename `WebhookEndpointJSONStatus` to `WebhookEndpointStatus`
    * Update method signatures and return types accordingly
  * **pipes:** Add pipes connected account event models
    * Add `PipeConnectedAccount` model with state tracking
    * Add `PipesConnectedAccountConnected`, `PipesConnectedAccountDisconnected`, `PipesConnectedAccountReauthorizationNeeded` event models
    * Add `PipeConnectedAccountState` enum with `connected` and `needs_reauthorization` values
    * Add webhook event types for pipes integration events
  * **generated:** Add new vault-related model types
    * Add `Actor` model for audit log actor representation
    * Add vault encryption models: `CreateDataKeyResponse`, `DecryptResponse`, `DeleteObjectResponse`
    * Add vault object models: `Object`, `ObjectMetadata`, `ObjectSummary`, `ObjectVersion`, `ObjectWithoutValue`
    * Add vault request models: `CreateDataKeyRequest`, `DecryptRequest`, `RekeyRequest`, `CreateObjectRequest`, `UpdateObjectRequest`
    * Add error and metadata models: `Error`, `ListMetadata`, `VersionListResponse`

* **session:** `Session.Refresh` now returns a non-nil error alongside the result on authentication-level failures (`refresh_token_revoked`, `refresh_failed`). The `RefreshSessionResult.Err` field has been removed — use the second return value instead. Callers should check `result.Authenticated` (not `err == nil`) as the success signal.

  **Migration:** replace `result.Err` with the `err` return value from `Refresh`:

  ```go
  // Before (v8)
  result, _ := session.Refresh(ctx)
  if !result.Authenticated {
      if result.Err != nil {
          var apiErr *workos.APIError
          errors.As(result.Err, &apiErr)
      }
  }

  // After (v9)
  result, err := session.Refresh(ctx)
  if !result.Authenticated {
      if err != nil {
          var apiErr *workos.APIError
          errors.As(err, &apiErr)
      }
  }
  ```

## [9.0.0](https://github.com/workos/workos-go/compare/v8.0.1...v9.0.0) (2026-05-26)


### ⚠ BREAKING CHANGES

* return error from Session.Refresh on auth failures ([#549](https://github.com/workos/workos-go/issues/549))
* **audit_logs:** Rename audit log model types (breaking) ([#554](https://github.com/workos/workos-go/issues/554))
* **radar:** Remove device_fingerprint and bot_score parameters ([#554](https://github.com/workos/workos-go/issues/554))
* **user_management:** Refactor organization membership to dedicated service ([#554](https://github.com/workos/workos-go/issues/554))

### Features

* **api_keys:** Add expires_at field to API key models ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **audit_logs:** Rename audit log model types (breaking) ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **authorization:** Add filter parameters to role/resource assignment list ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **generated:** Add new vault-related model types ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **organization_membership:** Add new organization membership service ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **pipes:** Add pipes connected account event models ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **radar:** Remove device_fingerprint and bot_score parameters ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **user_management:** Refactor organization membership to dedicated service ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **vault:** Add new vault service for encryption key management ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))
* **webhooks:** Rename webhook endpoint model type ([#554](https://github.com/workos/workos-go/issues/554)) ([0add116](https://github.com/workos/workos-go/commit/0add1169ca3254c962d312700208b1972dfd380d))


### Bug Fixes

* return error from Session.Refresh on auth failures ([#549](https://github.com/workos/workos-go/issues/549)) ([239fc22](https://github.com/workos/workos-go/commit/239fc227c6bd0675f2b23b3ae2e883fcaddcb462))

## [8.0.1](https://github.com/workos/workos-go/compare/v8.0.0...v8.0.1) (2026-05-13)


### Bug Fixes

* add URL escaping, JWT exp, and refresh errors ([#548](https://github.com/workos/workos-go/issues/548)) ([d6ba223](https://github.com/workos/workos-go/commit/d6ba223172fdd60c13cdbfdd7cf6c4319b876599))

## [8.0.0](https://github.com/workos/workos-go/compare/v7.1.2...v8.0.0) (2026-05-06)


### ⚠ BREAKING CHANGES

* **authorization:** Change email field type in multiple models
* **user_management:** Add user API key management endpoints
* **user_management:** Change email field type in user management models
* **authorization:** Rename RoleAssignment to UserRoleAssignment

### Features

* add API documentation site generation ([#546](https://github.com/workos/workos-go/issues/546)) ([b9701ea](https://github.com/workos/workos-go/commit/b9701eaaa2f8cb3da002c63564e10860e0aee15f))
* **api_keys:** Add organization and user API key models ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **authorization:** Add pagination order enum and update enum handling ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **authorization:** Change email field type in multiple models ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **authorization:** Rename RoleAssignment to UserRoleAssignment ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **authorization:** Unify BYOK key provider enum ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **directory_sync:** Add name field to directory user models ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **user_management:** Add name field to Profile and SSO models ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **user_management:** Add user API key management endpoints ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **user_management:** Add user field to organization membership models ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **user_management:** Change email field type in user management models ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))


### Bug Fixes

* **events:** Add admin_portal source to EventContextActorSource ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))
* **events:** Add vault.byok_key.deleted event type ([1b8f1d6](https://github.com/workos/workos-go/commit/1b8f1d6d3aaaf907c3c823d712e0b48f8d8a2480))

## [7.1.2](https://github.com/workos/workos-go/compare/v7.1.1...v7.1.2) (2026-05-01)


### Bug Fixes

* set canonical User-Agent header format ([#542](https://github.com/workos/workos-go/issues/542)) ([01d535f](https://github.com/workos/workos-go/commit/01d535fe47a0200ece0fb9d7e45f4cf04c888c0e))

## [7.1.1](https://github.com/workos/workos-go/compare/v7.1.0...v7.1.1) (2026-04-30)


### Bug Fixes

* parse webhook/action signature timestamps as milliseconds ([#539](https://github.com/workos/workos-go/issues/539)) ([ed9b464](https://github.com/workos/workos-go/commit/ed9b464746db86d0b4cd32ea197b8dc7277d0b6b))

## [7.1.0](https://github.com/workos/workos-go/compare/v7.0.0...v7.1.0) (2026-04-28)


### Features

* **generated:** Add Groups API and organization membership groups support ([#537](https://github.com/workos/workos-go/issues/537)) ([e9b53ed](https://github.com/workos/workos-go/commit/e9b53ed4ed537c8036cfdc7766b0e882e648f5e0))

## [7.0.0](https://github.com/workos/workos-go/compare/v6.5.0...v7.0.0) (2026-04-22)


### ⚠ BREAKING CHANGES

* v7 rewrites the SDK around the root `workos` package and a shared `workos.Client`, removing all legacy `pkg/*` imports, package-level `SetAPIKey`/`Configure` helpers, and compatibility re-exports.
* Service access now goes through `client.Service()` accessors, many method signatures changed, and list endpoints now return auto-paginating iterators instead of `List*Response` wrappers with `ListMetadata`.
* AuthKit/SSO/logout URL helpers changed, webhook verification now uses `workos.NewWebhookVerifier(...)`, `pkg/workos_errors` was removed in favor of new root error types, and Vault models have several incompatible shape and field-name changes.

See the [v7 migration guide](https://github.com/workos/workos-go/blob/main/docs/V7_MIGRATION_GUIDE.md) for the full upgrade checklist and code examples.

## [6.5.0](https://github.com/workos/workos-go/compare/v6.4.0...v6.5.0) (2026-03-20)


### Features

* **user-management:** add DirectoryManaged to OrganizationMembership ([#508](https://github.com/workos/workos-go/issues/508)) ([e9206b1](https://github.com/workos/workos-go/commit/e9206b1e4dd3fb134125dc63d484065e9fce7574))


### Bug Fixes

* allow clearing organization domains by sending empty arrays ([#522](https://github.com/workos/workos-go/issues/522)) ([a315391](https://github.com/workos/workos-go/commit/a3153914e5586b1e2ab139ce184ef618156b2157))
* directorysync.UserGroup: add missing fields ([#480](https://github.com/workos/workos-go/issues/480)) ([ba37619](https://github.com/workos/workos-go/commit/ba37619a0b6469af175065901a30e410e1d24249))
* organizations delete has wrong url casing ([#479](https://github.com/workos/workos-go/issues/479)) ([5de4629](https://github.com/workos/workos-go/commit/5de46296e2f53cf1c0bc24c7788dc9409b45b726))
* update renovate rules ([#504](https://github.com/workos/workos-go/issues/504)) ([4158a58](https://github.com/workos/workos-go/commit/4158a588e9baee7779ea9ce3bf883508eb6018ea))
