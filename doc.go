// @oagen-ignore-file

// Package workos provides a Go client for the WorkOS API.
//
// Create a client with your API key and optional client ID:
//
//	client := workos.NewClient(
//		"sk_...",
//		workos.WithClientID("client_..."),
//	)
//
// All API resources are accessed through service accessors on the Client.
// For example, to list organizations:
//
//	iter := client.Organizations().List(ctx, &workos.OrganizationsListParams{})
//	for iter.Next() {
//		org := iter.Current()
//		fmt.Println(org.Name)
//	}
//
// # Services
//
// The SDK exposes the following service groups:
//
//   - UserManagement: Users, authentication, invitations, organization memberships
//   - SSO: Single Sign-On connections, profiles, and SAML configuration
//   - Organizations: Organization CRUD and domain verification
//   - DirectorySync: Directory users, groups, and sync management
//   - Authorization: Fine-grained authorization (FGA) and RBAC
//   - AuditLogs: Audit log events and retention policies
//   - Vault: Encrypted key-value storage and client-side encryption
//   - Webhooks: Event construction and signature verification
//   - AdminPortal: Portal link generation
//   - Connect: Connect application management (OAuth & M2M)
//   - Events: Event stream
//   - FeatureFlags: Feature flag management and evaluation
//   - MultiFactorAuth: MFA challenges and verification
//   - Passwordless: Passwordless authentication sessions
//   - Radar: Radar list management
//   - Widgets: Widget token generation
//
// # Authentication
//
// Pass your API key as the first argument to NewClient. For operations that
// require a client ID (SSO, AuthKit, UserManagement auth flows), use
// WithClientID.
//
// # Error Handling
//
// API errors are returned as typed error values. Use errors.As to inspect them:
//
//	var notFound *workos.NotFoundError
//	if errors.As(err, &notFound) {
//		log.Printf("Resource not found: %s", notFound.Message)
//	}
//
// Error types: AuthenticationError (401), NotFoundError (404),
// UnprocessableEntityError (422), RateLimitExceededError (429),
// ServerError (5xx), NetworkError (connection failures).
//
// # Pagination
//
// List endpoints return an Iterator[T] that handles page fetching automatically.
// Call Next() to advance, Current() to read the item, and Err() to check for
// errors after iteration.
//
// # Retry
//
// The client automatically retries on 429 and 5xx status codes with exponential
// backoff and jitter. The Retry-After header is respected when present.
package workos
