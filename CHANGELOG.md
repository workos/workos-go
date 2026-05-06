# Changelog

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
