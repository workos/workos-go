# V7 Migration Guide

## Table Of Contents

- [V7 Migration Guide](#v7-migration-guide)
  - [Table Of Contents](#table-of-contents)
  - [Summary](#summary)
  - [Upgrade Checklist](#upgrade-checklist)
  - [1. Imports And Client Initialization](#1-imports-and-client-initialization)
    - [Before](#before)
    - [After](#after)
  - [2. Service Access Moves Behind `client.Service()`](#2-service-access-moves-behind-clientservice)
  - [3. Method Names And Parameter Shapes Are Simpler, But Different](#3-method-names-and-parameter-shapes-are-simpler-but-different)
    - [Organizations](#organizations)
    - [Directory Sync](#directory-sync)
    - [FGA / Authorization](#fga--authorization)
  - [4. List Endpoints Now Return Iterators Instead Of Response Wrappers](#4-list-endpoints-now-return-iterators-instead-of-response-wrappers)
    - [Before](#before-1)
    - [After](#after-1)
  - [5. AuthKit And SSO URL Helpers Changed](#5-authkit-and-sso-url-helpers-changed)
    - [AuthKit authorization URL](#authkit-authorization-url)
    - [SSO authorization URL](#sso-authorization-url)
    - [Logout URL generation](#logout-url-generation)
  - [6. Webhook Verification Has A New Entry Point](#6-webhook-verification-has-a-new-entry-point)
    - [Before](#before-2)
    - [After](#after-2)
  - [7. Error Handling Was Flattened](#7-error-handling-was-flattened)
    - [Before](#before-3)
    - [After](#after-3)
  - [8. Vault Models Changed Shape](#8-vault-models-changed-shape)
    - [Before](#before-4)
    - [After](#after-4)
  - [9. What Stayed The Same](#9-what-stayed-the-same)
  - [10. Recommended Migration Order](#10-recommended-migration-order)

## Summary

The public SDK surface has been rewritten around a single root `workos` package and a single `workos.Client`. The old `pkg/*` packages, package-level `SetAPIKey` / `Configure` helpers, response wrapper types, and `pkg/workos_errors` error package are gone.

## Upgrade Checklist

- Replace `pkg/*` imports with the root package: `github.com/workos/workos-go/v6`
- Replace package-level `SetAPIKey` / `Configure` calls with `workos.NewClient(...)`
- Replace package functions like `organizations.GetOrganization(...)` with `client.Organizations().Get(...)`
- Rewrite list handling from `List*Response{Data, ListMetadata}` to `Iterator[T]`
- Replace `pkg/workos_errors` usage with `errors.As` against `*workos.APIError` and the new status-based error types
- Replace `pkg/webhooks.NewClient(secret)` with `workos.NewWebhookVerifier(secret)`
- Rework AuthKit / SSO URL generation to use the new root helpers (`GetAuthKitAuthorizationURL`, `GetSSOAuthorizationURL`, `NewPublicClient`)

## 1. Imports And Client Initialization

The old SDK exposed many service-specific packages, each with its own default client and optional per-service `Client`. The new SDK exposes one root package and one shared client.

### Before

```go
import (
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/sso"
)

func main() {
	sso.Configure("<WORKOS_API_KEY>", "<CLIENT_ID>")
	directorysync.SetAPIKey("<WORKOS_API_KEY>")
}
```

### After

```go
import "github.com/workos/workos-go/v6"

func main() {
	client := workos.NewClient(
		"<WORKOS_API_KEY>",
		workos.WithClientID("<CLIENT_ID>"),
	)
}
```

What changed:

- All `pkg/*` imports are removed
- Global mutable default clients are removed
- Client configuration is now instance-scoped
- `WithHTTPClient`, `WithBaseURL`, `WithMaxRetries`, and `WithClientID` are set when constructing the shared client

## 2. Service Access Moves Behind `client.Service()`

The old package names and the new accessors do not line up one-for-one in code. Update service entry points as follows:

| Old package                | New accessor                                                                                       |
| -------------------------- | -------------------------------------------------------------------------------------------------- |
| `pkg/organizations`        | `client.Organizations()`                                                                           |
| `pkg/organization_domains` | `client.OrganizationDomains()`                                                                     |
| `pkg/sso`                  | `client.SSO()`                                                                                     |
| `pkg/directorysync`        | `client.DirectorySync()`                                                                           |
| `pkg/usermanagement`       | `client.UserManagement()`                                                                          |
| `pkg/auditlogs`            | `client.AuditLogs()`                                                                               |
| `pkg/fga`                  | `client.Authorization()`                                                                           |
| `pkg/portal`               | `client.AdminPortal()`                                                                             |
| `pkg/mfa`                  | `client.MultiFactorAuth()`                                                                         |
| `pkg/passwordless`         | `client.Passwordless()`                                                                            |
| `pkg/pipes`                | `client.Pipes()`                                                                                   |
| `pkg/vault`                | `client.Vault()`                                                                                   |
| `pkg/webhooks`             | `client.Webhooks()` for endpoint APIs, `workos.NewWebhookVerifier(...)` for signature verification |

There are no compatibility re-exports for the removed `pkg/*` import paths.

## 3. Method Names And Parameter Shapes Are Simpler, But Different

The old SDK usually passed an `Opts` struct containing path parameters. The new SDK usually takes path IDs as direct arguments and uses a pointer to a params struct only for request bodies or query parameters.

### Organizations

Before:

```go
import "github.com/workos/workos-go/v6/pkg/organizations"

organizations.SetAPIKey("<WORKOS_API_KEY>")

org, err := organizations.GetOrganization(ctx, organizations.GetOrganizationOpts{
	Organization: "org_123",
})
```

After:

```go
import "github.com/workos/workos-go/v6"

client := workos.NewClient("<WORKOS_API_KEY>")

org, err := client.Organizations().Get(ctx, "org_123")
```

Before:

```go
org, err := organizations.CreateOrganization(ctx, organizations.CreateOrganizationOpts{
	Name: "Acme",
})
```

After:

```go
org, err := client.Organizations().Create(ctx, &workos.OrganizationsCreateParams{
	Name: "Acme",
})
```

### Directory Sync

Before:

```go
import "github.com/workos/workos-go/v6/pkg/directorysync"

directorysync.SetAPIKey("<WORKOS_API_KEY>")

resp, err := directorysync.ListDirectories(ctx, directorysync.ListDirectoriesOpts{})
```

After:

```go
import "github.com/workos/workos-go/v6"

client := workos.NewClient("<WORKOS_API_KEY>")

iter := client.DirectorySync().List(ctx, &workos.DirectorySyncListParams{})
```

Notes:

- `ListDirectories` becomes `List`
- `GetDirectory` becomes `Get`
- `DeleteDirectory` becomes `Delete`
- `ListUsers` / `GetUser` and `ListGroups` / `GetGroup` still exist, but now hang off `client.DirectorySync()`

### FGA / Authorization

`pkg/fga` is now `Authorization`, and several names are different because the generated API surface follows Authorization endpoint naming more closely.

Before:

```go
import "github.com/workos/workos-go/v6/pkg/fga"

fga.SetAPIKey("<WORKOS_API_KEY>")

resp, err := fga.ListResources(ctx, fga.ListResourcesOpts{
	ResourceType: "project",
})
```

After:

```go
import "github.com/workos/workos-go/v6"

client := workos.NewClient("<WORKOS_API_KEY>")
resourceType := "project"

iter := client.Authorization().ListResources(ctx, &workos.AuthorizationListResourcesParams{
	ResourceTypeSlug: &resourceType,
})
```

## 4. List Endpoints Now Return Iterators Instead Of Response Wrappers

This is one of the biggest source changes.

### Before

```go
resp, err := organizations.ListOrganizations(ctx, organizations.ListOrganizationsOpts{
	Limit: 10,
})
if err != nil {
	return err
}

for _, org := range resp.Data {
	fmt.Println(org.ID)
}

fmt.Println(resp.ListMetadata.After)
```

### After

```go
limit := 10

iter := client.Organizations().List(ctx, &workos.OrganizationsListParams{
	PaginationParams: workos.PaginationParams{
		Limit: &limit,
	},
})

for iter.Next() {
	fmt.Println(iter.Current().ID)
}

if err := iter.Err(); err != nil {
	return err
}
```

What changed:

- `List*Response` types are removed from most public list flows
- The SDK now auto-fetches subsequent pages with `Iterator[T]`
- `ListMetadata` is no longer returned to callers
- Existing code that stored cursors, exposed `before` / `after`, or rendered explicit next-page controls needs to be rewritten

If you were using manual cursor management, this branch does not currently provide a drop-in page object replacement.

## 5. AuthKit And SSO URL Helpers Changed

The old SDK built authorization and logout URLs directly from `pkg/sso` and `pkg/usermanagement`. The generated service methods in this branch are not the right replacement for that old usage. Use the new root helper methods instead.

### AuthKit authorization URL

Before:

```go
import "github.com/workos/workos-go/v6/pkg/usermanagement"

u, err := usermanagement.GetAuthorizationURL(usermanagement.GetAuthorizationURLOpts{
	ClientID:    "<WORKOS_CLIENT_ID>",
	RedirectURI: "https://example.com/callback",
	Provider:    "authkit",
})
```

After:

```go
import "github.com/workos/workos-go/v6"

client := workos.NewClient(
	"<WORKOS_API_KEY>",
	workos.WithClientID("<WORKOS_CLIENT_ID>"),
)
provider := "authkit"

u, err := client.GetAuthKitAuthorizationURL(workos.AuthKitAuthorizationURLParams{
	RedirectURI: "https://example.com/callback",
	Provider:    &provider,
})
```

For browser/public PKCE flows, prefer:

```go
publicClient := workos.NewPublicClient("<WORKOS_CLIENT_ID>")
result, err := publicClient.GetAuthorizationURL(workos.AuthKitAuthorizationURLParams{
	RedirectURI: "https://example.com/callback",
})
```

### SSO authorization URL

Before:

```go
import "github.com/workos/workos-go/v6/pkg/sso"

sso.Configure("<WORKOS_API_KEY>", "<WORKOS_CLIENT_ID>")

u, err := sso.GetAuthorizationURL(sso.GetAuthorizationURLOpts{
	RedirectURI:  "https://example.com/callback",
	Organization: "org_123",
})
```

After:

```go
import "github.com/workos/workos-go/v6"

client := workos.NewClient(
	"<WORKOS_API_KEY>",
	workos.WithClientID("<WORKOS_CLIENT_ID>"),
)
organizationID := "org_123"

u, err := client.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{
	RedirectURI:    "https://example.com/callback",
	OrganizationID: &organizationID,
})
```

### Logout URL generation

Before:

```go
u, err := usermanagement.GetLogoutURL(usermanagement.GetLogoutURLOpts{
	SessionID: "session_abc",
	ReturnTo:  "https://example.com/signed-out",
})
```

After:

```go
session := workos.NewSession(client, sealedSession, cookiePassword)
u, err := session.GetLogoutURL(ctx, "https://example.com/signed-out")
```

Notes:

- The old URL-building helpers returned `*url.URL`
- The maintained root helpers now return `string`
- The generated `client.UserManagement().GetAuthorizationURL(...)` and `client.UserManagement().GetLogoutURL(...)` methods are not a drop-in replacement for the old client-side URL builders

## 6. Webhook Verification Has A New Entry Point

Webhook endpoint management moved onto `client.Webhooks()`, but signature verification is no longer a `pkg/webhooks.Client`.

### Before

```go
import "github.com/workos/workos-go/v6/pkg/webhooks"

client := webhooks.NewClient(secret)
body, err := client.ValidatePayload(header, rawBody)
```

### After

```go
import "github.com/workos/workos-go/v6"

verifier := workos.NewWebhookVerifier(secret)
body, err := verifier.VerifyPayload(header, rawBody)
```

Constructing an event is also separate now:

```go
event, err := verifier.ConstructEvent(header, rawBody)
```

Additional breaking changes:

- Error names changed:
  - `ErrInvalidHeader` -> `ErrWebhookInvalidHeader`
  - `ErrNoValidSignature` -> `ErrWebhookNoValidSignature`
  - `ErrNotSigned` -> `ErrWebhookNotSigned`
  - `ErrInvalidTimestamp` -> `ErrWebhookInvalidTimestamp`
  - `ErrOutsideTolerance` -> `ErrWebhookOutsideTolerance`
- Test helpers that previously signed headers with millisecond timestamps need to switch to Unix seconds:

Before:

```go
stringTime := strconv.FormatInt(now.Round(0).Unix()*1000, 10)
```

After:

```go
timestamp := strconv.FormatInt(now.Unix(), 10)
```

## 7. Error Handling Was Flattened

The old SDK exposed `pkg/workos_errors` with `HTTPError`, `FieldErrors`, and several structured authentication errors.

### Before

```go
import "github.com/workos/workos-go/v6/pkg/workos_errors"

var mfaErr *workos_errors.MFAChallengeError
if errors.As(err, &mfaErr) {
	fmt.Println(mfaErr.PendingAuthenticationToken)
}
```

### After

```go
import "github.com/workos/workos-go/v6"

var apiErr *workos.APIError
if errors.As(err, &apiErr) && apiErr.Code == "mfa_challenge" {
	fmt.Println(apiErr.Message)
}
```

What changed:

- `pkg/workos_errors` is removed
- `HTTPError` is removed
- `IsBadRequest` is removed
- Structured auth errors like `MFAChallengeError`, `SSORequiredError`, and `OrganizationSelectionRequiredError` are removed
- Error typing is now mostly status-based:
  - `*workos.AuthenticationError`
  - `*workos.NotFoundError`
  - `*workos.UnprocessableEntityError`
  - `*workos.RateLimitExceededError`
  - `*workos.ServerError`
  - `*workos.NetworkError`

Important limitation:

- The old error package exposed extra auth-specific fields like `PendingAuthenticationToken`, `EmailVerificationID`, `AuthenticationFactors`, `Organizations`, `ConnectionIDs`, `SSOConnectionIDs`, and `AuthMethods`
- The new `APIError` only exposes `StatusCode`, `RequestID`, `RetryAfter`, `Code`, and `Message`
- If your application branches on those richer auth error payloads, there is no one-to-one replacement in this branch

## 8. Vault Models Changed Shape

Vault still exists, but several public model shapes changed in incompatible ways.

### Before

```go
import "github.com/workos/workos-go/v6/pkg/vault"

pair, err := vault.CreateDataKey(ctx, vault.CreateDataKeyOpts{
	KeyContext: vault.KeyContext{
		"environment": "env_123",
	},
})
if err != nil {
	return err
}

fmt.Println(pair.DataKey)
```

### After

```go
import "github.com/workos/workos-go/v6"

pair, err := client.Vault().CreateDataKey(ctx, &workos.VaultCreateDataKeyParams{
	Context: workos.KeyContext{
		Type:          "environment",
		EnvironmentID: "env_123",
	},
})
if err != nil {
	return err
}

fmt.Println(pair.DataKey.Key)
```

Important Vault model changes:

- `KeyContext` changed from `map[string]interface{}` to a struct
- `Object` became `VaultObject`
- `ObjectDigest` became `VaultObjectDigest`
- `ObjectVersion` became `VaultObjectVersion`
- `DataKeyPair.DataKey` changed from `string` to `DataKey`
- Many `Id` / `EnvironmentId` / `KeyId` fields are now `ID` / `EnvironmentID` / `KeyID`
- Some timestamp fields that were `time.Time` are now `string`

## 9. What Stayed The Same

- The core WorkOS products are still present: SSO, Directory Sync, Organizations, User Management, Audit Logs, Vault, Webhooks, and more
- Context-aware request methods are still used for network calls
- API key and client ID concepts are unchanged
- Automatic retry behavior is still present for `429` and `5xx`
- `Retry-After` is still honored
- `POST` requests still get an idempotency key automatically
- Vault local encryption helpers still exist

## 10. Recommended Migration Order

1. Replace imports and initialize a shared `workos.Client`
2. Rewrite package-level calls to `client.Service()` accessors
3. Rewrite list calls to iterators
4. Update auth helper usage to the new root helper methods
5. Replace `pkg/workos_errors` error matching with `errors.As` against new root error types
6. Update webhook verification and any custom webhook test fixtures
7. Audit Vault call sites for renamed fields and model shape changes
