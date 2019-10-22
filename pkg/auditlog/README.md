# alog

A Go package to asynchronously send audit logs events to WorkOS.

## Install

```sh
go get -u github.com/workos-inc/workos-go/pkg/auditlog
```

## How it works

```go
package main

import "github.com/workos-inc/workos-go/pkg/auditlog"

func main() {
    alog.SetAPIKey("my_api_key")
    defer alog.Close()

    // Wherever you need to publish an audit log event:
    alog.Publish(alog.Event{
        Action:     "document.viewed",
        ActionType: "r",
        ActorName:  "Jairo Kunde",
        ActorID:    "user_01DGZ0FAXN978HCET66Q98QMTQ",
        Group:      "abstract.com",
        Location:   "55.27.223.26",
        OccurredAt: time.Now(),
        TargetName: "central.class",
        TargetID:   "doc_01DGZ0FAXP4HA4X0BVFKS0ZH4Y",
    })
}
```
