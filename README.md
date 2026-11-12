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

## Workload identity

A workload that already has an identity on its platform, such as a GitHub Actions job, a Google Cloud service account or an AWS IAM role, can call the WorkOS API without a stored API key. The SDK exchanges the platform's identity token for a short-lived WorkOS access token and sends that instead.

Build the credentials, then build the client from them:

```go
creds, err := workos.NewWorkloadIdentityCredentials(workos.WorkloadIdentityConfig{
	ClientID:              "<WORKOS_CLIENT_ID>",
	TokenURL:              "<WORKOS_WIF_TOKEN_URL>",
	EnvironmentID:         "<WORKOS_ENVIRONMENT_ID>",
	IdentityTokenProvider: provider, // see below
})
if err != nil {
	log.Fatal(err)
}

client := workos.NewClientWithCredentials(creds)
```

| Field                   | Environment variable    | Required | Description                                                     |
| ----------------------- | ----------------------- | -------- | --------------------------------------------------------------- |
| `ClientID`              | `WORKOS_CLIENT_ID`      | yes      | The M2M application's client ID                                 |
| `TokenURL`              | `WORKOS_WIF_TOKEN_URL`  | yes      | The token endpoint; there is no built-in default                |
| `EnvironmentID`         | `WORKOS_ENVIRONMENT_ID` | yes      | The environment the requests are for                            |
| `IdentityTokenProvider` | -                       | yes      | Returns the workload's identity token                           |
| `Resource`              | -                       | no       | Defaults to `https://api.workos.com`                            |
| `Scope`                 | `WORKOS_WIF_SCOPE`      | no       | Left out of the exchange when empty                             |
| `HTTPClient`            | -                       | no       | Sends the exchange request; redirects are never followed        |

A field left empty is read from its environment variable, and a required setting that is still missing is an error from `NewWorkloadIdentityCredentials`. The environment variables only fill in credentials you construct: nothing switches workload identity on by itself, and a client built with credentials never falls back to an API key.

### Identity token providers

A provider is a function that returns the workload's identity token. Each platform's provider is its own Go module, so the SDK takes on no new dependencies; install only the one you use. The audience must match the audience of the trust rule in WorkOS.

**GitHub Actions**

```bash
go get github.com/workos/workos-go/workloadidentity/githubactions
```

```go
provider := githubactions.New("https://api.workos.com")
```

The workflow or job must grant the token permission:

```yaml
permissions:
  id-token: write
```

**Google Cloud**

```bash
go get github.com/workos/workos-go/workloadidentity/gcp
```

```go
provider := gcp.New("https://api.workos.com")
```

The token comes from the metadata server, for the default service account of the Compute Engine, GKE, Cloud Run or Cloud Functions workload.

**AWS**

```bash
go get github.com/workos/workos-go/workloadidentity/aws
```

```go
import workosaws "github.com/workos/workos-go/workloadidentity/aws"

provider, err := workosaws.New(ctx, workosaws.Options{
	Audience: "https://api.workos.com",
	Region:   "us-east-1", // optional when the AWS SDK can resolve a region
})
```

The token comes from STS `GetWebIdentityToken`, so the IAM identity needs the `sts:GetWebIdentityToken` permission. This is the only module that depends on the AWS SDK.

**Anything else**

```go
// A file the platform rotates, such as a Kubernetes projected service account token.
provider := workos.TokenFileProvider("/var/run/secrets/tokens/workos")

// An environment variable.
provider = workos.TokenEnvProvider("MY_IDENTITY_TOKEN")

// Any function with this signature.
provider = func(ctx context.Context) (string, error) {
	return fetchIdentityToken(ctx)
}
```

### How it behaves

- The access token is cached in memory on the credentials value and exchanged again shortly before it expires. Concurrent requests share one exchange. Reuse one credentials value, and one client, for the life of the process.
- If the API answers 401, the client discards that token, exchanges again and repeats the request once.
- The exchange is retried on network failures, 429 and 5xx, and the provider is called again for each attempt.
- A failure to get a token is a `*workos.WorkloadIdentityError`. Its `Code` is the OAuth error code from the token endpoint (`invalid_grant`, `invalid_client`, ...) or one of `exchange_failed`, `invalid_response`, `provider_failed` and `invalid_configuration`; its `Hint` says what to check.

```go
_, err := client.Organizations().Get(ctx, "org_123")

var wifErr *workos.WorkloadIdentityError
if errors.As(err, &wifErr) {
	log.Printf("workload identity failed (%s): %s", wifErr.Code, wifErr.Hint)
}
```

> [!NOTE]
> A client built with `NewClientWithCredentials` holds no API key. The methods that send the API key as a client secret, `UserManagement().AuthenticateWith...` and `SSO().GetProfileAndToken`, need a client built with `NewClient`.

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

The cookie password must be at least 32 bytes long (32 ASCII characters;
multibyte UTF-8 characters count by their byte length). Use a high-entropy secret;
length alone does not make a predictable passphrase safe. We recommend a
64-character hex string encoding 32 random bytes, generated with
`openssl rand -hex 32`. Valid 64-character hex keys are decoded directly;
other passwords meeting the minimum are hashed with SHA-256, as before.
This requirement also applies to the generic `Seal`/`Unseal` and
`SealData`/`UnsealData` helpers.

Upgrading does not invalidate existing sessions sealed under an already-compliant
password: key derivation is unchanged, so no re-login is required. Applications
using empty or shorter passwords must rotate to a strong, compliant secret,
which invalidates their existing cookies and requires users to log in again.
These weak-password cookies are vulnerable to forgery and cannot safely be
preserved. Sealing with a short password returns an error; authenticating a
cookie with one returns `Authenticated: false` and `Reason: "invalid_session_cookie"`.

Authenticate and refresh user sessions using sealed cookies:

```go
session := workos.NewSession(client, sealedCookie, cookiePassword)

result, err := session.Authenticate()
if errors.Is(err, workos.ErrSigningKeyUnavailable) {
	// The signing key could not be fetched, so the token was not judged.
	// Keep the session cookie and retry on a later request.
	return
}
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

When the signing key cannot be obtained (the JWKS request failed, timed out or
was canceled), `Authenticate` returns `Reason: "jwks_unavailable"` and an error
matching `workos.ErrSigningKeyUnavailable`. The token was not judged, so keep
the session cookie and retry instead of signing the user out.

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
