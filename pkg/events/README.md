# events

A Go package to retrieve events from WorkOS.

## Install

```sh
go get -u github.com/workos/workos-go/v4/pkg/events
```

## How it works

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/workos/workos-go/v4/pkg/events"
)

func main() {
	events.SetAPIKey(os.Getenv("WORKOS_API_KEY"))

	eventTypes := []string{
		"dsync.activated",
		"dsync.deleted",
		"dsync.user.created",
		"dsync.user.updated",
		"dsync.user.deleted",
	}

	events, err := events.ListEvents(context.Background(), events.ListEventsOpts{
		Events: eventTypes,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", events)
}
```
