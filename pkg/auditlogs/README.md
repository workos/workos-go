# auditlogs

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos/workos-go/v6/pkg/auditlogs)auditlogs

A Go package to send audit log events to WorkOS.

## Install

```sh
go get -u github.com/workos/workos-go/v6/pkg/auditlogs
```

## How it works

```go
package main

import "github.com/workos/workos-go/v6/pkg/auditlogs"auditlogs

func main() {
	auditlogs.SetAPIKey("my_api_key")

	// Wherever you need to publish an audit log event:
	err := auditlogs.CreateEvent(ctx.Background(), auditlogs.CreateEventOpts{
		Organization: "org_8899300049990088",
		Event: Event{
			Action: "team.created",
			Actor: Actor{
				ID:   "o5fdfsdfUMCAuunNN3Iwfs34gMw",
				Name: "jonatas",
				Type: "user",
				Metadata: map[string]interface{}{
					"Email": "person@workos.com",
				},
			},
			Context: Context{
				Location: "79.226.116.209",
			},
			Targets: []Target{
				Target{ID: "team_123", Type: "team"},
			},
		},
		IdempotencyKey: uuid.New().String(),
	})
}
if err != nil {
// Handle error.
}
}
```
