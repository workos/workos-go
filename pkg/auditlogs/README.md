# auditlogs

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos/workos-go/pkg/auditlogs)

A Go package to send audit log events to WorkOS.

## Install

```sh
go get -u github.com/workos/workos-go/pkg/auditlogs
```

## How it works

```go
package main

import "github.com/workos/workos-go/pkg/auditlogs"

func main() {
    auditlogs.SetAPIKey("my_api_key")

    // Wherever you need to publish an audit trail event:
    err := auditlogs.CreateEvent(ctx.Background(), auditlogs.EventOpts{
        Action:     "document.viewed",
        ActionType: audittrail.Create,
        ActorName:  "Jairo Kunde",
        ActorID:    "user_01DGZ0FAXN978HCET66Q98QMTQ",
        Group:      "abstract.com",
        Location:   "55.27.223.26",
        OccurredAt: time.Now(),
        TargetName: "central.class",
        TargetID:   "doc_01DGZ0FAXP4HA4X0BVFKS0ZH4Y",
    })
    if err != nil {
        // Handle error.
    }
}
```
