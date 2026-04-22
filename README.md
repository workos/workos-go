<!-- @oagen-ignore-file -->

# WorkOS Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/workos/workos-go/v7.svg)](https://pkg.go.dev/github.com/workos/workos-go/v7)

The WorkOS Go library provides a flat, root-level `workos` package for applications written in Go.

## Installation

```bash
go get github.com/workos/workos-go/v7
```

## Usage

```go
package main

import (
	"context"
	"log"

	"github.com/workos/workos-go/v7"
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

| Accessor | Description |
|---|---|
| `APIKeys()` | Organization API key management |
| `AdminPortal()` | Admin Portal link generation |
| `AuditLogs()` | Audit log events and retention |
| `Authorization()` | Fine-grained authorization (FGA) and RBAC |
| `Connect()` | Connect application management |
| `DirectorySync()` | Directory Sync (directories, users, groups) |
| `Events()` | Event stream |
| `FeatureFlags()` | Feature flag management and evaluation |
| `MultiFactorAuth()` | Multi-factor authentication challenges |
| `OrganizationDomains()` | Organization domain verification |
| `Organizations()` | Organization CRUD |
| `Passwordless()` | Passwordless authentication sessions |
| `Pipes()` | Data integration pipes |
| `Radar()` | Radar list management |
| `SSO()` | Single Sign-On connections and profiles |
| `UserManagement()` | Users, invitations, auth methods |
| `Vault()` | Key-value storage and client-side encryption |
| `Webhooks()` | Webhook event construction and verification |
| `Widgets()` | Widget token generation |

## Error Handling

The SDK returns typed errors that can be inspected with `errors.Is` and `errors.As`:

| Type | HTTP Status | Description |
|---|---|---|
| `AuthenticationError` | 401 | Invalid or missing API key |
| `NotFoundError` | 404 | Requested resource does not exist |
| `UnprocessableEntityError` | 422 | Validation errors |
| `RateLimitExceededError` | 429 | Rate limit exceeded (auto-retried) |
| `ServerError` | 5xx | WorkOS server error (auto-retried) |
| `NetworkError` | - | Connection failure |

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

List endpoints return an `Iterator[T]` for auto-pagination:

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

Verify incoming webhook payloads and construct typed events:

```go
v := workos.NewWebhookVerifier(secret)

payload, err := v.VerifyPayload(sigHeader, rawBody)
if err != nil {
	log.Fatal("invalid webhook signature")
}

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
if result.Authenticated {
	fmt.Println("User:", result.User)
	fmt.Println("Org:", result.OrganizationID)
}

refreshed, err := session.Refresh(ctx)
if refreshed.Authenticated {
	// Set refreshed.SealedSession as the new cookie value
}
```

## Vault

Store and retrieve encrypted key-value data with client-side encryption:

```go
// KV operations
obj, _ := client.Vault().CreateObject(ctx, &workos.VaultCreateObjectParams{
	Name: "api-token", Value: "secret-value",
})
read, _ := client.Vault().ReadObject(ctx, obj.ID)

// Client-side encryption (AES-256-GCM)
encrypted, _ := client.Vault().Encrypt(ctx, "sensitive data", keyContext, "")
decrypted, _ := client.Vault().Decrypt(ctx, encrypted.EncryptedData, "")
```

## Request Options

Customize individual requests with functional options:

```go
result, err := client.Organizations().Get(ctx, "org_123",
	workos.WithTimeout(5 * time.Second),
	workos.WithIdempotencyKey("unique-key"),
	workos.WithExtraHeaders(http.Header{"X-Custom": {"value"}}),
)
```

## AuthKit / SSO Helpers

Build authorization URLs client-side without making HTTP requests:

```go
// AuthKit with PKCE
result, err := client.GetAuthKitPKCEAuthorizationURL(workos.AuthKitAuthorizationURLParams{
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

This SDK is a Go library, so it uses a flat package layout at the module root rather than an application-style project layout.

- The public API lives in the root `workos` package.
- Tests are colocated in `*_test.go` files, which is idiomatic for Go libraries.
- Request and response fixtures live in `testdata/`.

Import the root package:

```go
import "github.com/workos/workos-go/v7"
```
