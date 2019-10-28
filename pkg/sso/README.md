# sso

[![godoc](https://godoc.org/github.com/workos-inc/workos-go/pkg/sso?status.svg)](https://godoc.org/github.com/workos-inc/workos-go/pkg/sso)

A go package to request WorkOS SSO API.

## How it works

```go
import (
    "context"
    "fmt"
    "net/http"

    "github.com/workos-inc/workos-go/pkg/sso"
)

func main() {
    sso.SetAPIKey("my_api_key")

    http.Handle("/login", sso.Login(sso.GetAuthorizationURLOptions{
        Domain:      "mydomain.com",
        ProjectID:   "my_workos_project_id",
        RedirectURI: "https://mydomain.com/callback",
    }))

    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        profile, err := sso.GetProfile(context.Background(), sso.GetProfileOptions{
            Code:        r.URL.Query().Get("code"),
            ProjectID:   "my_workos_project_id",
            RedirectURI: "https://mydomain.com/callback",
        })
        if err != nil {
            // Handle the error ...
            return
        }

        // Handle the profile ...
        fmt.Println(profile)
    })

    if err := http.ListenAndServe("your_server_addr", nil); err != nil {
        panic(err)
    }
}
```
