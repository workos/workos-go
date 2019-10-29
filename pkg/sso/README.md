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
    sso.Configure(
        "xxxxx",                            // WorkOS api key
        "project_xxxxx",                    // WorkOS project id
        "https://mydomain.com/callback",    // Redirect URI
    )

    http.Handle("/login", sso.Login(sso.GetAuthorizationURLOptions{
        Domain: "mydomain.com",
    }))

    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        profile, err := sso.GetProfile(context.Background(), sso.GetProfileOptions{
            Code:   r.URL.Query().Get("code"),
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
