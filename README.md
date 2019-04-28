# WorkOS

A WorkOS client for your Go applications making it easy to publish Audit Log.

## Installation

You can install the WorkOS library in your local environment by running:

```
go get -u github.com/dewski/workos
```

## Usage

Creating an Audit Log event requires a descriptive action name and annotating the event with its CRUD identifier. The action name must contain an action category and an action name seperated by a period, for example, `user.login`.

```go
user := User{
  ID: 1,
  Email: "user@email.com",
}
event := auditlog.NewEvent("user.login", auditlog.Create)
event.SetActor(user)
event.SetTarget(user)
event.SetLocation("1.1.1.1")
err := event.Publish()
if err != nil {
  fmt.Printf("Had a problem writing the event: %q %q\n", event, err)
}
```

This event being sent to WorkOS would look like:

```json
{
  "group": "twitter",
  "action": "user.login",
  "action_type": "C",
  "actor_name": "user@email.com",
  "actor_id": "user_1",
  "target_name": "user@email.com",
  "target_id": "user_1",
  "location": "1.1.1.1",
  "occured_at": "2019-05-01T01:15:55.619355Z",
  "metadata": {}
}
```

Notice you didn't need to set the group name or the time it occurred. These fields are automatically populated for you at the time the event is created. Should you want to configure what the group name is set the `WORKOS_GROUP` environment variable.

## Configuring An Auditable Interface

In the previous example notice how we configured the actor and target to the User struct. Given that the struct supports the `Auditable` interface the Audit Log can be populated with a human and machine representation of it. To support the `Auditable` interface you must have a `ToAuditableName` and `ToAuditableID` function with the same function signatures:

```go
type user struct {
	Email      string
	DatabaseID int
}

func (u user) ToAuditableName() string {
	return u.Email
}

func (u user) ToAuditableID() string {
	return strconv.Itoa(u.DatabaseID)
}
```

As long as your structs support the `Auditable` interface you can pass your structs to `SetActor` and `SetTarget` and it will automatically be included in the published event.

## Adding Metadata To Events

Metadata provides added context directly to your events that would be helpful in the future when looking at an Audit Log event.

You can add metadata directly to events

```go
user := User{
  ID: 1,
  Email: "user@email.com",
}
tweet := Tweet{
  ID: 5,
  Body: "What time is the event",
}
bodyWas := comment.Body
tweet.Body = "What time is the event?"

event := auditlog.NewEvent("tweet.update", auditlog.Update)
event.SetActor(user)
event.SetTarget(tweet)
event.SetLocation("1.1.1.1")
event.AddMetadata(map[string]interface{}{
  "body_was": bodyWas,
  "body": comment.Body,
})
err := event.Publish()
if err != nil {
  fmt.Printf("Had a problem writing the event: %q %q\n", event, err)
}
```

Resulting in the following being sent to WorkOS:

```json
{
  "group": "twitter",
  "action": "tweet.update",
  "action_type": "U",
  "actor_name": "user@email.com",
  "actor_id": "user_1",
  "target_name": "user@email.com",
  "target_id": "tweet_5",
  "location": "1.1.1.1",
  "occured_at": "2019-05-01T01:15:55.619355Z",
  "metadata": {
    "body_was": "What time is the event",
    "body": "What time is the event?"
  }
}
```

By adding supportive metadata in the future you can not only see who updated the tweet, which tweet, but also what the original tweet body was and what the body was updated to. For something like a tweet which could get updated multiple times, you can't always depend on the database representation. Good Audit Log events log all the supporting information surrounding the event which could be used to inform the reader in the future what exactly happened and how it happened.

## Configuring Global Metadata

As mentioned before, a good Audit Log event contains all the supporting information surrounding the event. If you wanted to attach the hostname this particular event took place on for debugging purposes you'd use `auditlog.SetMetadata`:

```go
package main

import (
	"os"

	"github.com/dewski/workos/auditlog"
)

func main() {
  location, err := os.Hostname()
  if err != nil {
    location = ""
  }

  auditlog.SetMetadata(map[string]interface{}{
    "hostname": location,
  })

  // Your code goes here
}
```

Using the previous example the event sent to WorkOS would look like:

```json
{
  "group": "twitter",
  "action": "tweet.update",
  "action_type": "U",
  "actor_name": "user@email.com",
  "actor_id": "user_1",
  "target_name": "user@email.com",
  "target_id": "tweet_5",
  "location": "1.1.1.1",
  "occured_at": "2019-05-01T01:15:55.619355Z",
  "metadata": {
    "body_was": "What time is the event",
    "body": "What time is the event?",
    "hostname": "app-fe1.aws.amazon.com"
  }
}
```

## Using With HTTP Request

When creating an Audit Log event that was triggered as a result of an HTTP request you can use the `NewEventWithHTTP` function to automatically populate the event with helpful information about the request. The request's IP address, user agent, request ID, and request URL will all automatically be added to the event for you.

```go
http.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
  user := User{
    Email:      "me@domain.com",
    DatabaseID: 1,
  }

  event := auditlog.NewEventWithHTTP("user.login", auditlog.Create, req)
  event.SetActor(user)
  event.SetTarget(user)
  err := event.Publish()
  if err != nil {
    fmt.Printf("Had a problem writing the event: %q %q\n", event, err)
  }

  body, _ := json.Marshal(event)
  fmt.Fprintf(w, string(body))
})
```

```json
{
  "group": "twitter",
  "action": "tweet.update",
  "action_type": "U",
  "actor_name": "user@email.com",
  "actor_id": "user_1",
  "target_name": "user@email.com",
  "target_id": "tweet_5",
  "location": "172.31.255.255",
  "occured_at": "2019-05-01T01:15:55.619355Z",
  "metadata": {
    "body_was": "What time is the event",
    "body": "What time is the event?",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
    "request_url": "http://localhost/tweet/update",
    "request_id": "f9ed4675f1c53513c61a3b3b4e25b4c0",
    "http_method": "PUT"
  }
}
```
