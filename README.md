<!-- @oagen-ignore-file -->

# WorkOS Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/workos/workos-go/v10.svg)](https://pkg.go.dev/github.com/workos/workos-go/v10)

The WorkOS Go library provides a flat, root-level `workos` package for applications written in Go.

## Installation

Requires Go `1.23+`.

```bash
go get github.com/workos/workos-go/v10
```

## Usage

```go
package main

import (
	"context"
	"log"

	"github.com/workos/workos-go/v10"
)

func main() {
	client := workos.NewClient(
		"<WORKOS_API_KEY>",
		workos.WithClientID("<WORKOS_CLIENT_ID>"),
	)

	organization, err := client.Organizations().Get(context.Background(), "org_123")
	if err != nil {
		log.Fatal(err)
	}

	_ = organization
}
```

## Services

All API resources are accessed through service accessors on the `Client`:

| Accessor                | Description                                  |
| ----------------------- | -------------------------------------------- |
| `APIKeys()`                  | Organization API key management              |
| `AdminPortal()`              | Admin Portal link generation                 |
| `AuditLogs()`                | Audit log events and retention               |
| `Authorization()`            | Roles, permissions, resources, and authorization checks |
| `ClientAPI()`                | Client API token generation                  |
| `Connect()`                  | Connect application management               |
| `DirectorySync()`            | Directory Sync (directories, users, groups)  |
| `Events()`                   | Event stream                                 |
| `FeatureFlags()`             | Feature flag management and targeting        |
| `Groups()`                   | Organization group management                |
| `MultiFactorAuth()`          | Multi-factor authentication challenges       |
| `OrganizationDomains()`      | Organization domain verification             |
| `OrganizationMembership()`   | Organization membership management           |
| `Organizations()`            | Organization CRUD                            |
| `Passwordless()`             | Passwordless authentication sessions         |
| `Pipes()`                    | Data integration pipes                       |
| `PipesProvider()`            | Organization data integration configuration  |
| `Radar()`                    | Radar risk assessment and list management    |
| `SSO()`                      | Single Sign-On connections and profiles      |
| `UserManagement()`           | Users, invitations, auth methods             |
| `Vault()`                    | Key-value storage and client-side encryption |
| `Webhooks()`                 | Webhook endpoint management                  |
| `Widgets()`                  | Widget token generation                      |

## Error Handling

The SDK returns typed errors that can be inspected with `errors.As`, including the base `*workos.APIError`:

| Type                       | HTTP Status | Description                        |
| -------------------------- | ----------- | ---------------------------------- |
| `AuthenticationError`      | 401         | Invalid or missing API key         |
| `NotFoundError`            | 404         | Requested resource does not exist  |
| `UnprocessableEntityError` | 422         | Validation errors                  |
| `RateLimitExceededError`   | 429         | Rate limit exceeded (auto-retried) |
| `ServerError`              | 5xx         | WorkOS server error (500/502/503/504 auto-retried) |
| `NetworkError`             | -           | Connection failure                 |

```go
result, err := client.Organizations().Get(ctx, "org_123")
if err != nil {
	var notFound *workos.NotFoundError
	if errors.As(err, &notFound) {
		log.Printf("Organization not found: %s", notFound.Message)
	}
}
```

## Pagination

Paginated list endpoints return an `Iterator[T]` for auto-pagination:

```go
iter := client.UserManagement().List(ctx, &workos.UserManagementListParams{})
for iter.Next() {
	user := iter.Current()
	fmt.Println(user.Email)
}
if err := iter.Err(); err != nil {
	log.Fatal(err)
}
```

## Webhook Verification

Manage webhook endpoints with `client.Webhooks()`. Verify incoming webhook payloads with `workos.NewWebhookVerifier(...)`:

```go
v := workos.NewWebhookVerifier(secret)

// rawBody is the request body as a string, e.g. string(bodyBytes).
payload, err := v.VerifyPayload(sigHeader, rawBody)
if err != nil {
	log.Fatal("invalid webhook signature")
}
_ = payload

event, err := v.ConstructEvent(sigHeader, rawBody)
if err != nil {
	log.Fatal(err)
}
fmt.Println(event.Event, event.ID)
```

## Session Management

Authenticate and refresh user sessions using sealed cookies:

```go
session := workos.NewSession(client, sealedCookie, cookiePassword)

result, err := session.Authenticate()
if err != nil {
	log.Fatal(err)
}
if result.Authenticated {
	fmt.Println("User:", result.User)
	fmt.Println("Org:", result.OrganizationID)
}

refreshed, err := session.Refresh(ctx)
if err != nil {
	log.Fatal(err)
}
if refreshed.Authenticated {
	// Set refreshed.SealedSession as the new cookie value
}
```

## Vault

Store and retrieve encrypted key-value data with client-side encryption:

```go
// KV operations
keyContext := map[string]string{"organization_id": "org_123"}

obj, _ := client.Vault().CreateKv(ctx, &workos.VaultCreateKvParams{
	Name: "api-token", Value: "secret-value", KeyContext: keyContext,
})
read, _ := client.Vault().GetKv(ctx, obj.ID)

// Client-side encryption (AES-256-GCM)
encrypted, _ := client.Vault().Encrypt(ctx, "sensitive data", keyContext, "")
decrypted, _ := client.Vault().Decrypt(ctx, encrypted.EncryptedData, "")
```

## Request Options

Customize individual requests with functional options:

```go
result, err := client.Organizations().Get(ctx, "org_123",
	workos.WithTimeout(5 * time.Second),
	workos.WithExtraHeaders(http.Header{"X-Custom": {"value"}}),
)
```

> [!NOTE]
> The SDK automatically attaches an `Idempotency-Key` header (a random UUID, reused across automatic retries) to every `POST` request; use `workos.WithIdempotencyKey` to supply your own. The WorkOS API currently deduplicates on this key only for the [Create Audit Log Event](https://workos.com/docs/reference/audit-logs/event) endpoint (`AuditLogs().CreateEvent`). Other endpoints accept the header but do not deduplicate requests, so a retried mutation elsewhere can still create a duplicate.

## AuthKit / SSO Helpers

Build authorization URLs without making HTTP requests. For browser or other public PKCE flows, prefer `workos.NewPublicClient(...)`:

```go
// AuthKit with PKCE
publicClient := workos.NewPublicClient("<WORKOS_CLIENT_ID>")

result, err := publicClient.GetAuthorizationURL(workos.AuthKitAuthorizationURLParams{
	RedirectURI: "https://example.com/callback",
})
fmt.Println(result.URL)          // redirect the user here
fmt.Println(result.CodeVerifier) // store securely for token exchange

// SSO authorization
url, err := client.GetSSOAuthorizationURL(workos.SSOAuthorizationURLParams{
	RedirectURI: "https://example.com/sso/callback",
	ConnectionID: &connID,
})
```

## Package Layout

This SDK is a Go library that uses a flat package layout at the module root rather than an application-style project layout.

- The public API lives in the root `workos` package; event type constants are additionally available in `github.com/workos/workos-go/v*/pkg/events`.
- Tests are colocated in `*_test.go` files, which is idiomatic for Go libraries.
- Request and response fixtures live in `testdata/`.

Import the root package:

```go
import "github.com/workos/workos-go/v10"
```
