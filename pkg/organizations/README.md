# organizations

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos/workos-go/v5/pkg/organizations)

A Go package to make requests to the WorkOS Organizations API.

## Install

```sh
go get -u github.com/workos/workos-go/v5/pkg/organizations
```

## How it works

See the [Organizations API reference](https://workos.com/docs/reference/organization).

### Update organization metadata and remove a key by sending JSON null

To set a metadata value to null (and remove it server-side), pass a `nil` pointer for that key. The `Metadata` field accepts `map[string]*string`.

```go
region := "us-west"
org, err := organizations.UpdateOrganization(ctx, organizations.UpdateOrganizationOpts{
  Organization: "org_123",
  Metadata: map[string]*string{
    "region": &region,
    "legacy_id": nil, // serializes as JSON null
  },
})
```
