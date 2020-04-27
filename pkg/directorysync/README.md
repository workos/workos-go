# directorysync

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos-inc/workos-go/pkg/directorysync)

A Go package to make requests to the WorkOS Directory Sync API.

## Install

```sh
go get -u github.com/workos-inc/workos-go/pkg/directorysync
```

## How it works

You first need to setup a Directory on [workos.com](https://dashboard.workos.com/directory-sync).

```go
package main

import "github.com/workos-inc/workos-go/pkg/directorysync"

func main() {
  directorysync.SetAPIKey("my_api_key")

  directoryUsers, err := directorysync.ListUsers(
    context.Background(),
    directorysync.ListUsersOpts{
      Directory: "directory_id",
    },
  )
  if err != nil {
      // Handle error.
  }
}
```
