# usermanagement

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos/workos-go/v5/pkg/usermanagement)

A go package wrapping the WorkOS User Management API.

## Install

```sh
go get -u github.com/workos/workos-go/v5/pkg/usermanagement
```

## How it works

See the [User Management integration guide](https://workos.com/docs/user-management/).

### Update user metadata and remove a key by sending JSON null

To set a metadata value to null (and remove it server-side), pass a `nil` pointer for that key. The `Metadata` field accepts `map[string]*string`.

```go
lang := "en"
user, err := usermanagement.UpdateUser(ctx, usermanagement.UpdateUserOpts{
  User: "user_123",
  Metadata: map[string]*string{
    "language": &lang,
    "legacy_code": nil, // serializes as JSON null
  },
})
```
