# WorkOS

A WorkOS client for Go applications in your organization to control and monitor the access of information within your organization.

## Installation

You can install the WorkOS Go client in your local environment by running:

```
go get -u github.com/workos-inc/workos-go
```

## Configuration

To use the client you must provide an API key located from the WorkOS dashboard either as an environment variable `WORKOS_API_KEY`:

```sh
WORKOS_API_KEY="sk_1234" ./app
```

Or you can set it on your own before your application starts:

```go
package main

import "github.com/workos-inc/workos-go/auditlog"

func main() {
	auditlog.SetAPIKey("sk_1234")

	// application code
}
```

## Usage

Creating an Audit Log event requires a descriptive action name and annotating the event with its CRUD identifier. The action name must contain an action category and an action name seperated by a period, for example, `user.login`.

```go
user := User{
  ID: 1,
  Email: "user@email.com",
}
organization := Organization{
  ID: 1,
  Name: "workos",
}
event := auditlog.NewEvent("user.login", auditlog.Create)
event.SetGroup(organization)
event.SetActor(user)
event.SetTarget(user)
event.SetLocation("1.1.1.1")
event.Publish()
```

The resulting event being sent to WorkOS looks like:

```json
{
  "group": "organization_1",
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

The time the event occured is automatically populated for you when the event is created.

All events are published to WorkOS asyncronously by default. `auditlog.Publish` returns an error channel for you so you can wait for a response from WorkOS should you need a blocking operation.

```go
user := User{
  ID: 1,
  Email: "user@email.com",
}
organization := Organization{
  ID: 1,
  Name: "workos",
}
event := auditlog.NewEvent("user.login", auditlog.Create)
event.SetGroup(organization)
event.SetActor(user)
event.SetTarget(user)
event.SetLocation("1.1.1.1")
ch := event.Publish()
err := <-ch
if err != nil {
  fmt.Printf("Had a problem writing the event: %q %q\n", event, err)
}
```

## Configuring An Auditable Interface

In the previous example notice how we configured the actor and target to be the `User` struct and the group to the `Organization` struct. As long as your structs support the `auditlog.Auditable` interface the Audit Log can be populated with a human and machine readable version of its values. To support the `auditlog.Auditable` interface you must have a `ToAuditableName` and `ToAuditableID` function with the same signatures as shown below:

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

## Adding Metadata To Events

Metadata provides additional context for your Audit Log events that would be helpful to you or others in the future when looking at an Audit Log event. Values for your metadata are expected to be primitive types:

- string
- bool
- int, int8, int16, int32, int64
- float32, float64
- time.Time
- err

_You're allowed to have maps with its elements being any one of the primitive types._

You can add metadata directly to events by using `auditlog.AddMetadata`:

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
event.SetGroup(user)
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
  "group": "user_1",
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

By adding supportive metadata when you create the event you can see what the original tweet body was and what the body was updated to. For something like a tweet which could get updated multiple times over the course of time, you can't always depend on the database representation to tell you what the body has always been. Without logging it right when the change occures, you'll forever lose all the individual changes along the way. Good Audit Log events attach all supporting information surrounding the event which could be used to inform the reader in the future what exactly happened, how it happened, and when it happened.

## Adding Other Structs To Metadata

While the event's actor and target are first-class properties of the event, you can also use any struct that implements the `auditlog.Auditable` interface in your metadata. When you add it to your event's metadata it will automatically be expanded for you based on the original key name.

```go
user := User{
	ID: 1,
	Email: "user@email.com",
}
parentTweet := Tweet{
	ID: 5,
	Body: "What time is the event",
}
tweet := Tweet{
	ID: 6,
	Body: "It's at 6:30 PM",
	ParentTweet: parentTweet,
}

event := auditlog.NewEvent("tweet.create", auditlog.Update)
event.SetGroup(user)
event.SetActor(user)
event.SetTarget(tweet)
event.SetLocation("1.1.1.1")
event.AddMetadata(map[string]interface{}{
	"parent_tweet": tweet.ParentTweet,
})
err := event.Publish()
if err != nil {
	fmt.Printf("Had a problem writing the event: %q %q\n", event, err)
}
```

Resulting in the following being sent to WorkOS:

```json
{
  "group": "user_1",
  "action": "tweet.create",
  "action_type": "C",
  "actor_name": "user@email.com",
  "actor_id": "user_1",
  "target_name": "It's at 6:30 PM",
  "target_id": "tweet_6",
  "location": "1.1.1.1",
  "occured_at": "2019-05-01T01:15:55.619355Z",
  "metadata": {
    "parent_tweet_name": "What time is the event",
    "parent_tweet_id": "tweet_5"
  }
}
```

## Configuring Global Metadata

As mentioned before, a good Audit Log event contains all the supporting information surrounding the event at the time it took place. If you wanted to attach the hostname this particular event took place on for debugging purposes you'd use `auditlog.SetMetadata`:

```go
package main

import (
	"os"

	"github.com/workos-inc/workos-go/auditlog"
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

When creating an Audit Log event that was triggered as a result of an HTTP request you can use the `auditlog.NewEventWithHTTP` function to automatically populate the event with helpful information about the request. The request's IP address, user agent, request ID, HTTP method, and request URL will all automatically be added to the event for you.

```go
http.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
	user := User{
		Email:      "me@domain.com",
		DatabaseID: 1,
	}

	event := auditlog.NewEventWithHTTP("user.login", auditlog.Create, req)
	event.SetGroup(user)
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
  "action": "user.login",
  "action_type": "U",
  "actor_name": "user@email.com",
  "actor_id": "user_1",
  "target_name": "user@email.com",
  "target_id": "user_1",
  "location": "172.31.255.255",
  "occured_at": "2019-05-01T01:15:55.619355Z",
  "metadata": {
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
    "request_url": "http://localhost/tweet/update",
    "request_id": "f9ed4675f1c53513c61a3b3b4e25b4c0",
    "http_method": "PUT"
  }
}
```

## Paginating Events

This client provides auto pagination when querying events. This feature easily handles fetching large lists of events without having to manually paginate results and perform subsequent requests. Optional parameters `Limit`, `StartingAfter`, and `EndingBefore` can be provided to query. If both `StartingAfter` and `EndingBefore` are provided, the client will default to using only `EndingBefore`.

```go
  i := events.List(auditlog.ListRequestParams{Limit: 20, EndingBefore: "evt_01DARZVVM933M93J6XREKWS436"})
	for i.Next() {
		event := i.Event()
		log.Println(event.ID)
  }
```
