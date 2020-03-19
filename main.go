package main

import (
	"context"
	"fmt"

	"github.com/workos-inc/workos-go/pkg/sso"
)

func main() {
	sso.Configure(
		"sk_live_Ee18IIIycKcqqu20Yu28agiCK",
		"project_01DGR79RCHD8ECW0391ZV5M7MQ",
		"https://workos.dev/callback",
	)

	profile, err := sso.GetProfile(context.Background(), sso.GetProfileOptions{
		Code: "hello world",
	})

	fmt.Println(profile, err)

}
