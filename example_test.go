// @oagen-ignore-file

package workos_test

import (
	"context"
	"fmt"
	"log"

	"github.com/workos/workos-go/v8"
)

func ExampleNewClient() {
	client := workos.NewClient(
		"sk_example_api_key",
		workos.WithClientID("client_example_id"),
	)

	// Use client to access services
	_ = client.Organizations()
	_ = client.UserManagement()
	_ = client.SSO()

	fmt.Println("client created")
	// Output: client created
}

func ExampleIterator() {
	client := workos.NewClient("sk_example_api_key")

	iter := client.Organizations().List(context.Background(), &workos.OrganizationsListParams{})
	for iter.Next() {
		org := iter.Current()
		fmt.Println(org.Name)
	}
	if err := iter.Err(); err != nil {
		log.Fatal(err)
	}
}
