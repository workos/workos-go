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
