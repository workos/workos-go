// @oagen-ignore-file

package workos

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// IdentityTokenProvider returns the workload's identity token: the JWT that
// workload identity credentials exchange for a WorkOS access token.
//
// It is called again for every exchange attempt, so it may return a new token
// each time; returning the same one is fine. It should honor ctx, which
// carries the deadline of the exchange: a call still running at the deadline
// is abandoned and its result discarded. The provider can then be called
// again while the abandoned call is still running, so it must be safe for
// concurrent calls. It must not put the token in an error.
//
// Any function with this signature is a provider. TokenFileProvider and
// TokenEnvProvider cover the common cases, and the modules under
// github.com/workos/workos-go/workloadidentity provide one for GitHub
// Actions, Google Cloud and AWS.
type IdentityTokenProvider func(ctx context.Context) (string, error)

// TokenFileProvider returns a provider that reads the identity token from a
// file, such as a projected service account token. The file is read again on
// every call, so a rotated token is picked up, and surrounding whitespace is
// trimmed. A missing or empty file is an error.
func TokenFileProvider(path string) IdentityTokenProvider {
	return func(context.Context) (string, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("workos: reading the identity token file: %w", err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("workos: the identity token file %s is empty", path)
		}
		return token, nil
	}
}

// TokenEnvProvider returns a provider that reads the identity token from an
// environment variable. The variable is read again on every call. An unset or
// empty variable is an error.
func TokenEnvProvider(name string) IdentityTokenProvider {
	return func(context.Context) (string, error) {
		token := os.Getenv(name)
		if token == "" {
			return "", fmt.Errorf("workos: the environment variable %s is not set or is empty", name)
		}
		return token, nil
	}
}
