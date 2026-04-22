# Changelog

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
