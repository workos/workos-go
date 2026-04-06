<!-- @oagen-ignore-file -->

# WorkOS Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/workos/workos-go/v6.svg)](https://pkg.go.dev/github.com/workos/workos-go/v6)

The WorkOS Go library provides a flat, root-level `workos` package for applications written in Go.

## Installation

```bash
go get github.com/workos/workos-go/v6
```

## Usage

```go
package main

import (
	"context"
	"log"

	"github.com/workos/workos-go/v6"
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

## Package Layout

This SDK is a Go library, so it uses a flat package layout at the module root rather than an application-style project layout.

- The public API lives in the root `workos` package.
- Tests are colocated in `*_test.go` files, which is idiomatic for Go libraries.
- Request and response fixtures live in `testdata/`.

Import the root package:

```go
import "github.com/workos/workos-go/v6"
```
