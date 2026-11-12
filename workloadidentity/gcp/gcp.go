// Package gcp provides the Google Cloud identity token for WorkOS workload
// identity federation.
//
// New returns a provider that asks the metadata server for an ID token of
// the workload's default service account. It works wherever the metadata
// server is available: Compute Engine, GKE, Cloud Run, Cloud Functions and
// App Engine. Pass it to the WorkOS SDK as the identity token provider:
//
//	creds, err := workos.NewWorkloadIdentityCredentials(workos.WorkloadIdentityConfig{
//		IdentityTokenProvider: gcp.New("https://api.workos.com"),
//	})
//
// This module does not depend on the WorkOS SDK. The provider is a plain
// function, makes one HTTP request per call, and does no caching or retries;
// the SDK retries it as part of the token exchange.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	identityPath = "/computeMetadata/v1/instance/service-accounts/default/identity"

	requestTimeout = 10 * time.Second
	responseLimit  = 1 << 20
)

// metadataBaseURL is the metadata server. Tests point it at a mock; it is
// not a public option and is not read from the environment.
var metadataBaseURL = "http://metadata.google.internal"

// httpClient never follows a redirect. Its timeout keeps a workload that is
// not on Google Cloud, where the metadata host does not answer, from hanging.
var httpClient = &http.Client{
	Timeout: requestTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// New returns a provider of the metadata server's ID token for the given
// audience, which must match the audience of the trust rule in WorkOS; the
// conventional value is "https://api.workos.com".
func New(audience string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if audience == "" {
			return "", errors.New("gcp: an audience is required")
		}
		requestURL := metadataBaseURL + identityPath + "?audience=" + url.QueryEscape(audience) + "&format=full"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return "", fmt.Errorf("gcp: building the metadata request: %w", err)
		}
		req.Header.Set("Metadata-Flavor", "Google")

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("gcp: requesting the identity token from the metadata server: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("gcp: the metadata server returned HTTP %d", resp.StatusCode)
		}

		// The body is the token, so it never goes into an error.
		body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit))
		if err != nil {
			return "", fmt.Errorf("gcp: reading the metadata server's response: %w", err)
		}
		token := strings.TrimSpace(string(body))
		if token == "" {
			return "", errors.New("gcp: the metadata server returned no token")
		}
		return token, nil
	}
}
