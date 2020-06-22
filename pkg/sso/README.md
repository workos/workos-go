# sso

[![Go Report Card](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/workos-inc/workos-go/pkg/sso)

A go package to request WorkOS SSO API.

## Install

```sh
go get -u github.com/workos-inc/workos-go/pkg/sso
```

## How it works

You first need to setup an SSO connection on [workos.com](https://dashboard.workos.com/sso/connections).

Then implement the `/login` and `/callback` handlers on your server:

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
    )

    http.Handle("/login", sso.Login(sso.GetAuthorizationURLOptions{
        Domain: "mydomain.com",
        RedirectURI: "https://mydomain.com/callback",
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
