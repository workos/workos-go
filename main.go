package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/dewski/workos/auditlog"
	"github.com/dewski/workos/client"
)

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

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		u := user{
			Email:      "me@domain.com",
			DatabaseID: 1,
		}

		// We could maybe have a event.NewHTTPEvent() that takes the request
		// and populates it.
		event := auditlog.NewHTTPEvent("user.login", auditlog.Create, r)
		event.SetActor(u)
		event.SetTarget(u)

		err := client.PublishEvent(event)
		if err != nil {
			fmt.Println("Had a problem writing this event")
		}

		body, _ := json.Marshal(event)
		fmt.Fprintf(w, string(body))
	})
	log.Fatal(http.ListenAndServe(":8081", nil))
}
