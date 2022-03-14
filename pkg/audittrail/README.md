# audittrail

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos/workos-go/pkg/audittrail)

A Go package to send audit trails events to WorkOS.

## Install

```sh
go get -u github.com/workos/workos-go/pkg/audittrail
```

## How it works

```go
package main

import "github.com/workos/workos-go/pkg/audittrail"

func main() {
    audittrail.SetAPIKey("my_api_key")

    // Wherever you need to publish an audit trail event:
    err := audittrail.Publish(ctx.Background(), audittrail.EventOpts{
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
