# WorkOS

- Run with `go run main.go`
- Hit `localhost:8081/login` to see the event.
- Can configure endpoint the event is sent to with `WORKOS_ENDPOINT="https://someurl.com/process" go run main.go`
- Can configure API key with `WORKOS_API_KEY="token" go run main.go`
- Can set group for all events with `WORKOS_GROUP="myapp" go run main.go`
