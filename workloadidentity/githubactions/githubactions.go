// Package githubactions provides the GitHub Actions identity token for WorkOS
// workload identity federation.
//
// New returns a provider that asks GitHub for the job's OIDC token. Pass it
// to the WorkOS SDK as the identity token provider:
//
//	creds, err := workos.NewWorkloadIdentityCredentials(workos.WorkloadIdentityConfig{
//		IdentityTokenProvider: githubactions.New("https://api.workos.com"),
//	})
//
// The workflow or job must grant the token permission:
//
//	permissions:
//	  id-token: write
//
// This module does not depend on the WorkOS SDK. The provider is a plain
// function, makes one HTTP request per call, and does no caching or retries;
// the SDK retries it as part of the token exchange.
package githubactions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	requestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	requestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	requestTimeout = 10 * time.Second
	responseLimit  = 1 << 20
)

// httpClient never follows a redirect: the request token must not be sent to
// wherever the token endpoint points.
var httpClient = &http.Client{
	Timeout: requestTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// New returns a provider of the GitHub Actions OIDC token for the given
// audience, which must match the audience of the trust rule in WorkOS; the
// conventional value is "https://api.workos.com".
//
// The provider reads ACTIONS_ID_TOKEN_REQUEST_URL and
// ACTIONS_ID_TOKEN_REQUEST_TOKEN on every call. They are set only when the
// workflow or job has the permission "id-token: write".
func New(audience string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if audience == "" {
			return "", errors.New("githubactions: an audience is required")
		}
		requestURL := os.Getenv(requestURLEnv)
		requestToken := os.Getenv(requestTokenEnv)
		if requestURL == "" || requestToken == "" {
			return "", errors.New("githubactions: GitHub Actions did not provide an OIDC token endpoint. Add `permissions: id-token: write` to the workflow or job.")
		}

		// The URL GitHub provides already has a query string; add to it.
		separator := "&"
		if !strings.Contains(requestURL, "?") {
			separator = "?"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL+separator+"audience="+url.QueryEscape(audience), nil)
		if err != nil {
			return "", fmt.Errorf("githubactions: building the token request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+requestToken)
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("githubactions: requesting the OIDC token: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("githubactions: the OIDC token endpoint returned HTTP %d", resp.StatusCode)
		}

		// The body holds the token, so it never goes into an error.
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, responseLimit)).Decode(&body); err != nil {
			return "", errors.New("githubactions: the OIDC token endpoint returned a response that is not JSON")
		}
		if body.Value == "" {
			return "", errors.New("githubactions: the OIDC token endpoint returned no token")
		}
		return body.Value, nil
	}
}
