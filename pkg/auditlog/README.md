# auditlog

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos-inc/workos-go/pkg/auditlog)

A Go package to send audit logs events to WorkOS.

## Install

```sh
go get -u github.com/workos-inc/workos-go/pkg/auditlog
```

## How it works

```go
package main

import "github.com/workos-inc/workos-go/pkg/auditlog"

func main() {
    auditlog.SetAPIKey("my_api_key")

    // Wherever you need to publish an audit log event:
    err := auditlog.Publish(ctx.Background(), auditlog.Event{
        Action:     "document.viewed",
        ActionType: auditlog.Create,
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
