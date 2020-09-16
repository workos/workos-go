# portal

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos-inc/workos-go/pkg/portal)

A Go package to make requests to the WorkOS Admin Portal API.

## Install

```sh
go get -u github.com/workos-inc/workos-go/pkg/portal
```

## How it works

You first need to configure your Admin Portal settings on [workos.com](https://dashboard.workos.com/admin-portal).

```go
package main

import "github.com/workos-inc/workos-go/pkg/portal"

func main() {
  portal.SetAPIKey("my_api_key")

  organizations, err := portal.ListOrganizations(
    context.Background(),
    portal.ListOrganizationsOpts{
      Domains: []string{"foo-corp.com"},
    },
  )
  if err != nil {
      // Handle error.
  }
}
```
