// @oagen-ignore-file

package workos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// environmentIDHeader names the environment on every API request made
	// with workload identity credentials.
	environmentIDHeader = "x-url-environment-id"

	workloadIdentityGrantType       = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	workloadIdentityDefaultResource = "https://api.workos.com"

	// A cached token is replaced once less than
	// min(workloadIdentityMaxRefreshThreshold, lifetime/workloadIdentityRefreshDivisor)
	// of its lifetime remains: 60 seconds, or 20% for a short-lived token.
	workloadIdentityMaxRefreshThreshold = 60 * time.Second
	workloadIdentityRefreshDivisor      = 5

	// workloadIdentityDefaultLifetime is used when the token endpoint sends
	// no usable expires_in.
	workloadIdentityDefaultLifetime = 300 * time.Second

	// workloadIdentityExchangeDeadline bounds one shared exchange, including
	// its retries and backoff.
	workloadIdentityExchangeDeadline = 30 * time.Second

	// workloadIdentityResponseLimit caps how much of a token endpoint
	// response is read.
	workloadIdentityResponseLimit = 1 << 20
)

// WorkloadIdentityConfig configures NewWorkloadIdentityCredentials. An
// explicit value always wins over its environment variable.
type WorkloadIdentityConfig struct {
	// ClientID is the M2M application's client ID. Required; defaults to
	// WORKOS_CLIENT_ID.
	ClientID string
	// TokenURL is the token endpoint the identity token is exchanged at.
	// Required; defaults to WORKOS_WIF_TOKEN_URL. There is no built-in
	// default.
	TokenURL string
	// EnvironmentID is the WorkOS environment the requests are for. Required;
	// defaults to WORKOS_ENVIRONMENT_ID.
	EnvironmentID string
	// Resource is the resource the access token is requested for. Defaults
	// to "https://api.workos.com".
	Resource string
	// Scope is the scope requested for the access token. Defaults to
	// WORKOS_WIF_SCOPE; when empty, no scope is requested.
	Scope string
	// IdentityTokenProvider returns the workload's identity token. Required.
	IdentityTokenProvider IdentityTokenProvider
	// HTTPClient sends the exchange request. Optional. The credentials use a
	// copy of it that never follows redirects.
	HTTPClient *http.Client
}

// WorkloadIdentityCredentials authenticates a client with short-lived access
// tokens obtained by exchanging the workload's identity token, so no API key
// has to be stored. Pass it to NewClientWithCredentials.
//
// The access token is cached in memory on this value and refreshed on demand
// shortly before it expires. Concurrent callers share one exchange. Two
// WorkloadIdentityCredentials never share a token, even when configured
// identically. It is safe for concurrent use.
type WorkloadIdentityCredentials struct {
	clientID      string
	tokenURL      string
	environmentID string
	resource      string
	scope         string
	provider      IdentityTokenProvider
	httpClient    *http.Client

	// now, sleep and deadline are replaced by tests.
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
	deadline time.Duration // of one shared exchange

	mu         sync.Mutex
	token      string
	lifetime   time.Duration
	expiresAt  time.Time
	generation uint64 // 0 until the first token is stored
	inflight   *workloadIdentityExchange
}

var _ Credentials = (*WorkloadIdentityCredentials)(nil)

// workloadIdentityExchange is one shared exchange. Its result fields are
// written before done is closed and are read only after.
type workloadIdentityExchange struct {
	done       chan struct{}
	token      string
	generation uint64
	err        error
}

// NewWorkloadIdentityCredentials validates cfg and returns credentials for
// NewClientWithCredentials. Fields left empty are filled from the
// environment; a required setting that is still missing is an error here, not
// on the first request. The error is a *WorkloadIdentityError with the code
// "invalid_configuration".
//
// The configuration cannot be changed afterwards; build a new value instead.
func NewWorkloadIdentityCredentials(cfg WorkloadIdentityConfig) (*WorkloadIdentityCredentials, error) {
	c := &WorkloadIdentityCredentials{
		clientID:      firstNonEmpty(cfg.ClientID, os.Getenv("WORKOS_CLIENT_ID")),
		tokenURL:      firstNonEmpty(cfg.TokenURL, os.Getenv("WORKOS_WIF_TOKEN_URL")),
		environmentID: firstNonEmpty(cfg.EnvironmentID, os.Getenv("WORKOS_ENVIRONMENT_ID")),
		resource:      firstNonEmpty(cfg.Resource, workloadIdentityDefaultResource),
		scope:         firstNonEmpty(cfg.Scope, os.Getenv("WORKOS_WIF_SCOPE")),
		provider:      cfg.IdentityTokenProvider,
		now:           time.Now,
		sleep:         sleepContext,
		deadline:      workloadIdentityExchangeDeadline,
	}

	switch {
	case c.clientID == "":
		return nil, invalidWorkloadIdentityConfiguration("ClientID is required (or set WORKOS_CLIENT_ID)")
	case c.tokenURL == "":
		return nil, invalidWorkloadIdentityConfiguration("TokenURL is required (or set WORKOS_WIF_TOKEN_URL)")
	case c.environmentID == "":
		return nil, invalidWorkloadIdentityConfiguration("EnvironmentID is required (or set WORKOS_ENVIRONMENT_ID)")
	case c.provider == nil:
		return nil, invalidWorkloadIdentityConfiguration("IdentityTokenProvider is required")
	}
	if u, err := url.Parse(c.tokenURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, invalidWorkloadIdentityConfiguration("TokenURL must be an absolute http or https URL")
	}

	// The exchange never follows a redirect: the identity token must not be
	// replayed to wherever the token endpoint points.
	httpClient := http.Client{Timeout: defaultTimeout}
	if cfg.HTTPClient != nil {
		httpClient = *cfg.HTTPClient
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	c.httpClient = &httpClient

	return c, nil
}

// Resolve returns the headers that authorize one HTTP attempt: the access
// token and the environment ID. It reuses the cached token while it is fresh;
// otherwise it waits for a new one, starting an exchange unless one is
// already running. When ctx ends first, Resolve returns its error and the
// exchange carries on for the other callers.
func (c *WorkloadIdentityCredentials) Resolve(ctx context.Context) (CredentialSnapshot, error) {
	if c == nil || c.provider == nil {
		return CredentialSnapshot{}, invalidWorkloadIdentityConfiguration("the credentials were not built by NewWorkloadIdentityCredentials; check the error it returned")
	}

	c.mu.Lock()
	if c.fresh() {
		snapshot := c.snapshot(c.token, c.generation)
		c.mu.Unlock()
		return snapshot, nil
	}
	call := c.inflight
	if call == nil {
		call = &workloadIdentityExchange{done: make(chan struct{})}
		c.inflight = call
		go c.runExchange(call)
	}
	c.mu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
		return CredentialSnapshot{}, fmt.Errorf("workos: waiting for a workload identity token: %w", ctx.Err())
	}
	if call.err != nil {
		return CredentialSnapshot{}, call.err
	}
	return c.snapshot(call.token, call.generation), nil
}

// Invalidate discards the cached token if it is still the given generation,
// so the next Resolve exchanges again. A stale generation is ignored: a late
// 401 for an old token must not discard a newer one. It never blocks on the
// network.
func (c *WorkloadIdentityCredentials) Invalidate(generation uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation == c.generation {
		c.expiresAt = time.Time{}
	}
}

// fresh reports whether the cached token can still be sent. The caller holds
// c.mu.
func (c *WorkloadIdentityCredentials) fresh() bool {
	if c.token == "" {
		return false
	}
	threshold := min(workloadIdentityMaxRefreshThreshold, c.lifetime/workloadIdentityRefreshDivisor)
	return c.expiresAt.Sub(c.now()) >= threshold
}

func (c *WorkloadIdentityCredentials) snapshot(token string, generation uint64) CredentialSnapshot {
	headers := make(http.Header, 2)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set(environmentIDHeader, c.environmentID)
	return CredentialSnapshot{Headers: headers, Generation: generation}
}

// runExchange runs the shared exchange on its own deadline rather than on any
// caller's context, so a caller that gives up does not fail the others. It
// stores the result, clears the in-flight state and only then wakes the
// waiters, so a caller that gets an error and calls again starts a new
// exchange instead of joining the finished one.
func (c *WorkloadIdentityCredentials) runExchange(call *workloadIdentityExchange) {
	ctx, cancel := context.WithTimeout(context.Background(), c.deadline)
	defer cancel()

	var (
		token    string
		lifetime time.Duration
		// Replaced below; it stands only if the exchange panics.
		err error = newWorkloadIdentityError(workloadIdentityExchangeFailed, "the exchange did not complete", nil)
	)
	defer func() {
		c.mu.Lock()
		if err == nil {
			c.token = token
			c.lifetime = lifetime
			c.expiresAt = c.now().Add(lifetime)
			c.generation++
			call.token, call.generation = token, c.generation
		}
		call.err = err
		c.inflight = nil
		c.mu.Unlock()
		close(call.done)
	}()

	token, lifetime, err = c.exchange(ctx)
}

// exchange trades the identity token for an access token. It follows the
// same retry policy as API requests: transport failures, 429 and 5xx are
// retried with backoff, honoring Retry-After. The provider's failures are
// retried the same way, and the provider is called again for every attempt.
// Every other response is final.
func (c *WorkloadIdentityCredentials) exchange(ctx context.Context) (string, time.Duration, error) {
	var (
		lastErr    *WorkloadIdentityError
		retryAfter error // the last retryable response, for backoff
	)
	for attempt := 0; attempt <= defaultMaxRetries; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, backoff(attempt, retryAfter)); err != nil || ctx.Err() != nil {
				break // the exchange deadline passed
			}
		}
		retryAfter = nil

		assertion, err := c.identityToken(ctx)
		if err != nil {
			lastErr = newWorkloadIdentityError(workloadIdentityProviderFailed, err.Error(), err)
			continue
		}

		status, header, body, err := c.postAssertion(ctx, assertion)
		if err != nil {
			lastErr = newWorkloadIdentityError(workloadIdentityExchangeFailed, err.Error(), err)
			continue
		}

		// The status is checked before the body: a 429 or 5xx is retried even
		// when its body carries an OAuth error.
		fields := decodeJSONObject(body)
		if isRetryableExchangeStatus(status) {
			retryAfter = parseAPIError(&http.Response{StatusCode: status, Header: header, Body: http.NoBody})
			lastErr = oauthError(fields, assertion)
			if lastErr == nil {
				lastErr = newWorkloadIdentityError(workloadIdentityExchangeFailed, fmt.Sprintf("The token endpoint returned HTTP %d.", status), nil)
			}
			continue
		}

		if oauthErr := oauthError(fields, assertion); oauthErr != nil {
			return "", 0, oauthErr
		}
		switch {
		case status >= 300 && status <= 399:
			return "", 0, newWorkloadIdentityError(workloadIdentityExchangeFailed, fmt.Sprintf("The token endpoint answered with a redirect (HTTP %d), which is not followed.", status), nil)
		case status != http.StatusOK:
			return "", 0, newWorkloadIdentityError(workloadIdentityInvalidResponse, fmt.Sprintf("The token endpoint returned HTTP %d.", status), nil)
		case fields == nil:
			return "", 0, newWorkloadIdentityError(workloadIdentityInvalidResponse, "The response was not a JSON object.", nil)
		}
		token := jsonString(fields, "access_token")
		if token == "" {
			return "", 0, newWorkloadIdentityError(workloadIdentityInvalidResponse, "The response had no access_token.", nil)
		}
		return token, tokenLifetime(fields), nil
	}
	if lastErr == nil {
		lastErr = newWorkloadIdentityError(workloadIdentityExchangeFailed, "", ctx.Err())
	}
	return "", 0, lastErr
}

// identityToken calls the provider and waits for it no longer than the
// exchange deadline. A provider is asked to honor ctx, but one that does not,
// such as a read from a hung file system, must not hold the shared exchange
// open: the in-flight state has to clear when the deadline passes. The call
// is abandoned then, and its goroutine ends whenever the provider returns.
//
// The exchange runs where no caller can guard it, so a panic in the provider
// is reported as its failure instead of ending the process.
func (c *WorkloadIdentityCredentials) identityToken(ctx context.Context) (string, error) {
	type result struct {
		token string
		err   error
	}
	// Buffered, so a provider that returns after the deadline does not block.
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("the identity token provider panicked: %v", r)}
			}
		}()
		token, err := c.provider(ctx)
		done <- result{token: token, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return "", r.err
		}
		if r.token == "" {
			return "", errors.New("the identity token provider returned an empty token")
		}
		return r.token, nil
	case <-ctx.Done():
		return "", fmt.Errorf("the identity token provider did not return before the exchange deadline: %w", ctx.Err())
	}
}

// postAssertion sends one exchange request and returns the response with its
// body read. The form is rebuilt on every call. The request carries no client
// secret, no API key and no Authorization header.
func (c *WorkloadIdentityCredentials) postAssertion(ctx context.Context, assertion string) (int, http.Header, []byte, error) {
	form := url.Values{}
	form.Set("grant_type", workloadIdentityGrantType)
	form.Set("assertion", assertion)
	form.Set("client_id", c.clientID)
	form.Set("resource", c.resource)
	if c.scope != "" {
		form.Set("scope", c.scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "workos-go/"+Version)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, workloadIdentityResponseLimit))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, body, nil
}

// isRetryableExchangeStatus reports whether a token endpoint status is
// retried: every status the request path retries, and the rest of the 5xx
// range.
func isRetryableExchangeStatus(status int) bool {
	return isRetryableStatus(status) || (status >= 500 && status <= 599)
}

// oauthError returns the OAuth error carried by a token endpoint response, or
// nil when the body has no string "error" field. The assertion is removed
// from the server's text in case the endpoint echoes it.
func oauthError(fields map[string]json.RawMessage, assertion string) *WorkloadIdentityError {
	code := jsonString(fields, "error")
	if code == "" {
		return nil
	}
	redact := func(s string) string { return strings.ReplaceAll(s, assertion, "[redacted]") }
	return newWorkloadIdentityError(redact(code), redact(jsonString(fields, "error_description")), nil)
}

// decodeJSONObject returns the members of a JSON object, or nil when body is
// not one.
func decodeJSONObject(body []byte) map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil
	}
	return fields
}

// jsonString returns the named member when it is a JSON string, else "".
func jsonString(fields map[string]json.RawMessage, name string) string {
	var value string
	if raw, ok := fields[name]; ok && json.Unmarshal(raw, &value) == nil {
		return value
	}
	return ""
}

// tokenLifetime returns expires_in as a duration, or the default lifetime
// when it is absent, not a number or not positive.
func tokenLifetime(fields map[string]json.RawMessage) time.Duration {
	var seconds float64
	raw, ok := fields["expires_in"]
	if !ok || json.Unmarshal(raw, &seconds) != nil || !(seconds > 0) {
		return workloadIdentityDefaultLifetime
	}
	if seconds >= math.MaxInt64/float64(time.Second) {
		return math.MaxInt64
	}
	return time.Duration(seconds * float64(time.Second))
}

// sleepContext waits for d, or returns the context's error if it ends first.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
