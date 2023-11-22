# events 

A Go package to retrieve events from WorkOS.

## Install

```sh
go get -u github.com/workos/workos-go/v3/pkg/events
```

## How it works
```go

package main

import "github.com/workos/workos-go/v3/pkg/events"

func main() {
    events.SetAPIKey("my_api_key")

   var  events = []string {"dsync.user.created"}

    events, err := events.GetEvents(ctx.Background(), events.GetEventOpts{
        Event:     events,
    })
    if err != nil {
        // Handle error.
    }
}
```
