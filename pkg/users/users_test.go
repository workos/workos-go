package users

import (
	"context"
	"fmt"
	"testing"
)

// TODO: REMOVE sk_test_a2V5XzAxSDc4SDNaSEo4UERYN0JEQk03MUpTOEpBLGh3SkdEWnNGdGFTc01QclFkOW1LN1IzWnI

func TestGetUser2(t *testing.T) {
	SetApiKEY("sk_test_a2V5XzAxSDc4SDNaSEo4UERYN0JEQk03MUpTOEpBLGh3SkdEWnNGdGFTc01QclFkOW1LN1IzWnI")

	// Wherever you need to publish an audit log event:
	user, err := GetUser(context.Background(), GetUserOpts{
		User: "user_01H788AQPTNS48F8DCW5G92XNF",
	})
	if err != nil {
		// Handle error.
		fmt.Println(err)

	}

	fmt.Println(user)
}
