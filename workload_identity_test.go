// @oagen-ignore-file

package workos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The conformance cases for workload identity federation. Each TestWIF_NN
// function covers the case with that ID in conformance-cases.md; the tests
// named TestWIFExtra cover behavior the cases leave out. Everything runs
// against local mocks of the token endpoint and the API.

const (
	wifClientID      = "client_wif_test"
	wifEnvironmentID = "environment_wif_test"
	wifWaitLimit     = 10 * time.Second
)

// exchangeRecord is one POST the mock token endpoint received.
type exchangeRecord struct {
	method string
	path   string
	header http.Header
	form   url.Values
}

// tokenEndpoint is a mock of the token endpoint.
type tokenEndpoint struct {
	server *httptest.Server

	mu        sync.Mutex
	exchanges []exchangeRecord
	successes int
}

// newTokenEndpoint starts a mock token endpoint. respond answers the nth POST
// (counting from 1); nil answers every POST with the success response.
func newTokenEndpoint(t *testing.T, respond func(e *tokenEndpoint, n int, w http.ResponseWriter)) *tokenEndpoint {
	t.Helper()
	e := &tokenEndpoint{}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		e.mu.Lock()
		e.exchanges = append(e.exchanges, exchangeRecord{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			form:   form,
		})
		n := len(e.exchanges)
		e.mu.Unlock()
		if respond == nil {
			e.succeed(w)
			return
		}
		respond(e, n, w)
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *tokenEndpoint) url() string { return e.server.URL + "/oauth2/token" }

// count is the exchange count: the number of POSTs received.
func (e *tokenEndpoint) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.exchanges)
}

// exchange returns the nth POST received, counting from 1.
func (e *tokenEndpoint) exchange(n int) exchangeRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exchanges[n-1]
}

// nextToken names the access tokens access-1, access-2 and so on, one per
// successful exchange.
func (e *tokenEndpoint) nextToken() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.successes++
	return fmt.Sprintf("access-%d", e.successes)
}

// succeed writes the success response with the next access token.
func (e *tokenEndpoint) succeed(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":300}`, e.nextToken()))
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// writeOAuthError writes the OAuth error response.
func writeOAuthError(w http.ResponseWriter, code, description string) {
	writeJSON(w, http.StatusBadRequest, fmt.Sprintf(`{"error":%q,"error_description":%q}`, code, description))
}

// apiRecord is one request the mock API received.
type apiRecord struct {
	method string
	path   string
	header http.Header
	body   []byte
}

// apiMock is a mock of the WorkOS API.
type apiMock struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []apiRecord
}

// newAPIMock starts a mock API. respond answers the nth request (counting
// from 1); nil answers every request with an organization.
func newAPIMock(t *testing.T, respond func(n int, w http.ResponseWriter, r *http.Request)) *apiMock {
	t.Helper()
	a := &apiMock{}
	a.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.requests = append(a.requests, apiRecord{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   body,
		})
		n := len(a.requests)
		a.mu.Unlock()
		if respond == nil {
			writeOrganization(w)
			return
		}
		respond(n, w, r)
	}))
	t.Cleanup(a.server.Close)
	return a
}

func (a *apiMock) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

// request returns the nth request received, counting from 1.
func (a *apiMock) request(n int) apiRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests[n-1]
}

// authorizations lists the Authorization header of every request received.
func (a *apiMock) authorizations() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	values := make([]string, 0, len(a.requests))
	for _, r := range a.requests {
		values = append(values, r.header.Get("Authorization"))
	}
	return values
}

func writeOrganization(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, `{"id":"org_01","name":"Test Org"}`)
}

func writeUnauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, `{"message":"Unauthorized"}`)
}

// clearWIFEnv keeps the developer's environment out of a test.
func clearWIFEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"WORKOS_CLIENT_ID", "WORKOS_WIF_TOKEN_URL", "WORKOS_WIF_SCOPE", "WORKOS_ENVIRONMENT_ID"} {
		t.Setenv(name, "")
	}
}

// newTestCredentials builds credentials for the mock token endpoint with the
// fixture client and environment IDs. Exchange retries do not sleep.
func newTestCredentials(t *testing.T, e *tokenEndpoint, provider IdentityTokenProvider, configure ...func(*WorkloadIdentityConfig)) *WorkloadIdentityCredentials {
	t.Helper()
	clearWIFEnv(t)
	cfg := WorkloadIdentityConfig{
		ClientID:              wifClientID,
		TokenURL:              e.url(),
		EnvironmentID:         wifEnvironmentID,
		IdentityTokenProvider: provider,
	}
	for _, fn := range configure {
		fn(&cfg)
	}
	creds, err := NewWorkloadIdentityCredentials(cfg)
	require.NoError(t, err)
	creds.sleep = func(context.Context, time.Duration) error { return nil }
	return creds
}

// assertion returns a callback provider that always returns the same
// assertion and counts its calls: the provider count.
func assertion(value string, calls *atomic.Int32) IdentityTokenProvider {
	return func(context.Context) (string, error) {
		if calls != nil {
			calls.Add(1)
		}
		return value, nil
	}
}

func newWIFClient(creds Credentials, api *apiMock, opts ...ClientOption) *Client {
	return NewClientWithCredentials(creds, append([]ClientOption{WithBaseURL(api.server.URL)}, opts...)...)
}

// getOrganization makes one API request.
func getOrganization(client *Client) error {
	_, err := client.Organizations().Get(context.Background(), "org_01")
	return err
}

// requireWIFError asserts that err is a WorkloadIdentityError with the code.
func requireWIFError(t *testing.T, err error, code string) *WorkloadIdentityError {
	t.Helper()
	var wifErr *WorkloadIdentityError
	require.ErrorAs(t, err, &wifErr)
	require.Equal(t, code, wifErr.Code)
	require.NotEmpty(t, wifErr.Hint)
	return wifErr
}

// fakeClock is the injected clock. It starts at t=0 and only moves when told.
type fakeClock struct {
	mu      sync.Mutex
	start   time.Time
	elapsed time.Duration
}

func newFakeClock(creds *WorkloadIdentityCredentials) *fakeClock {
	clock := &fakeClock{start: time.Date(2026, time.November, 12, 0, 0, 0, 0, time.UTC)}
	creds.now = clock.now
	return clock
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.start.Add(c.elapsed)
}

// at moves the clock to the given time after t=0.
func (c *fakeClock) at(elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.elapsed = elapsed
}

// announcingCredentials reports every Resolve call before passing it on, so a
// test can tell when its callers have reached the credentials.
type announcingCredentials struct {
	Credentials
	entered func()
}

func (c announcingCredentials) Resolve(ctx context.Context) (CredentialSnapshot, error) {
	c.entered()
	return c.Credentials.Resolve(ctx)
}

// receive waits for a value, failing the test instead of hanging.
func receive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(wifWaitLimit):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// gate lets a mock hold its responses until the test opens it. Tests defer
// open, so a failing test does not leave a handler blocked while its server
// closes.
type gate struct {
	ch   chan struct{}
	once sync.Once
}

func newGate() *gate { return &gate{ch: make(chan struct{})} }

func (g *gate) wait() { <-g.ch }

func (g *gate) open() { g.once.Do(func() { close(g.ch) }) }

func TestWIF_01_ExchangeRequest(t *testing.T) {
	exchange := func(t *testing.T, scope string) exchangeRecord {
		endpoint := newTokenEndpoint(t, nil)
		api := newAPIMock(t, nil)
		creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil), func(cfg *WorkloadIdentityConfig) {
			cfg.Scope = scope
		})

		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		require.Equal(t, 1, endpoint.count(), "exchange count")
		post := endpoint.exchange(1)
		require.Equal(t, http.MethodPost, post.method)
		require.Equal(t, "/oauth2/token", post.path)
		require.Equal(t, "application/x-www-form-urlencoded", post.header.Get("Content-Type"))
		require.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", post.form.Get("grant_type"))
		require.Equal(t, "assertion-1", post.form.Get("assertion"))
		require.Equal(t, "client_wif_test", post.form.Get("client_id"))
		require.Equal(t, "https://api.workos.com", post.form.Get("resource"))
		require.False(t, post.form.Has("client_secret"), "the exchange must not send a client secret")
		require.Empty(t, post.header.Values("Authorization"), "the exchange must not send an Authorization header")
		return post
	}

	t.Run("without a scope", func(t *testing.T) {
		post := exchange(t, "")
		require.False(t, post.form.Has("scope"), "scope must be left out of the form when it is not set")
	})

	t.Run("with a scope", func(t *testing.T) {
		post := exchange(t, "organizations:write")
		require.Equal(t, []string{"organizations:write"}, post.form["scope"])
	})
}

func TestWIF_02_APIRequestCarriesTokenAndEnvironment(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	require.NoError(t, getOrganization(newWIFClient(creds, api)))

	require.Equal(t, 1, api.count())
	header := api.request(1).header
	require.Equal(t, []string{"Bearer access-1"}, header.Values("Authorization"))
	require.Equal(t, []string{"environment_wif_test"}, header.Values("x-url-environment-id"))
}

func TestWIF_03_SecondRequestReusesCachedToken(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	newFakeClock(creds)
	client := newWIFClient(creds, api)

	require.NoError(t, getOrganization(client))
	require.NoError(t, getOrganization(client))

	require.Equal(t, 1, endpoint.count(), "exchange count")
	require.Equal(t, []string{"Bearer access-1", "Bearer access-1"}, api.authorizations())
}

// requireRefreshBetween makes a request at t=0, one at stillFresh and one at
// stale. The first two must share one exchange; the third must cause a
// second. expiresIn is the "expires_in" member of the token response, or ""
// to leave it out.
func requireRefreshBetween(t *testing.T, expiresIn string, stillFresh, stale time.Duration) {
	t.Helper()
	endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, _ int, w http.ResponseWriter) {
		writeJSON(w, http.StatusOK, fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer"%s}`, e.nextToken(), expiresIn))
	})
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	clock := newFakeClock(creds)
	client := newWIFClient(creds, api)

	require.NoError(t, getOrganization(client))

	clock.at(stillFresh)
	require.NoError(t, getOrganization(client))
	require.Equal(t, 1, endpoint.count(), "exchange count at %s", stillFresh)

	clock.at(stale)
	require.NoError(t, getOrganization(client))
	require.Equal(t, 2, endpoint.count(), "exchange count at %s", stale)

	require.Equal(t, []string{"Bearer access-1", "Bearer access-1", "Bearer access-2"}, api.authorizations())
}

func TestWIF_04_RefreshesWhenLessThan60SecondsRemain(t *testing.T) {
	requireRefreshBetween(t, `,"expires_in":300`, 239*time.Second, 241*time.Second)
}

func TestWIF_05_ShortLifetimeRefreshesAt20Percent(t *testing.T) {
	requireRefreshBetween(t, `,"expires_in":100`, 79*time.Second, 81*time.Second)
}

func TestWIF_06_MissingExpiresInMeans300Seconds(t *testing.T) {
	requireRefreshBetween(t, "", 239*time.Second, 241*time.Second)
}

func TestWIF_07_InstancesDoNotShareACache(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	first := newWIFClient(newTestCredentials(t, endpoint, assertion("assertion-1", nil)), api)
	second := newWIFClient(newTestCredentials(t, endpoint, assertion("assertion-1", nil)), api)

	require.NoError(t, getOrganization(first))
	require.NoError(t, getOrganization(second))

	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, []string{"Bearer access-1", "Bearer access-2"}, api.authorizations())
}

func TestWIF_08_ConcurrentRequestsShareOneExchange(t *testing.T) {
	const callers = 20

	held := newGate()
	defer held.open()
	endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, _ int, w http.ResponseWriter) {
		held.wait()
		e.succeed(w)
	})
	api := newAPIMock(t, nil)
	var providerCalls atomic.Int32
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", &providerCalls))

	entered := make(chan struct{}, callers)
	client := newWIFClient(announcingCredentials{creds, func() { entered <- struct{}{} }}, api)

	results := make(chan error, callers)
	for range callers {
		go func() { results <- getOrganization(client) }()
	}
	// The token endpoint holds its response until every caller is waiting.
	for range callers {
		receive(t, entered, "a caller to reach the credentials")
	}
	held.open()

	for range callers {
		require.NoError(t, receive(t, results, "a request to finish"))
	}
	require.Equal(t, 1, endpoint.count(), "exchange count")
	require.Equal(t, int32(1), providerCalls.Load(), "provider count")
	require.Len(t, api.authorizations(), callers)
	for _, authorization := range api.authorizations() {
		require.Equal(t, "Bearer access-1", authorization)
	}
}

func TestWIF_09_UnauthorizedInvalidatesAndRetriesOnce(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			writeUnauthorized(w)
			return
		}
		writeOrganization(w)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	require.NoError(t, getOrganization(newWIFClient(creds, api)))

	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, []string{"Bearer access-1", "Bearer access-2"}, api.authorizations())
}

func TestWIF_10_SecondUnauthorizedIsReturned(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeUnauthorized(w)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	err := getOrganization(newWIFClient(creds, api))

	var authErr *AuthenticationError
	require.ErrorAs(t, err, &authErr)
	require.Equal(t, http.StatusUnauthorized, authErr.StatusCode)
	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, 2, api.count(), "API attempts")
}

func TestWIF_11_LateUnauthorizedKeepsNewerToken(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	ctx := context.Background()

	first, err := creds.Resolve(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Generation)
	require.Equal(t, "Bearer access-1", first.Headers.Get("Authorization"))

	creds.Invalidate(first.Generation)
	second, err := creds.Resolve(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(2), second.Generation)
	require.Equal(t, "Bearer access-2", second.Headers.Get("Authorization"))

	// A late 401 for the first token arrives after the second was fetched.
	creds.Invalidate(first.Generation)

	require.NoError(t, getOrganization(newWIFClient(creds, api)))
	current, err := creds.Resolve(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(2), current.Generation, "the cache must still hold generation 2")
	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, []string{"Bearer access-2"}, api.authorizations())
}

func TestWIF_12_TransportRetriesDoNotResetRecovery(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		switch n {
		case 1, 3:
			writeUnauthorized(w)
		case 2:
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusServiceUnavailable, `{"message":"Service Unavailable"}`)
		default:
			writeOrganization(w)
		}
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	err := getOrganization(newWIFClient(creds, api))

	var authErr *AuthenticationError
	require.ErrorAs(t, err, &authErr)
	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, 3, api.count(), "API attempts: 401, 503, 401 and no fourth")
	require.Equal(t, []string{"Bearer access-1", "Bearer access-2", "Bearer access-2"}, api.authorizations())
}

func TestWIF_13_RecoveryResendsSameBodyAndIdempotencyKey(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			writeUnauthorized(w)
			return
		}
		writeOrganization(w)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	_, err := newWIFClient(creds, api).Organizations().Create(context.Background(), &OrganizationsCreateParams{Name: "Acme"})
	require.NoError(t, err)

	require.Equal(t, 2, api.count(), "API attempts")
	first, second := api.request(1), api.request(2)
	require.Equal(t, http.MethodPost, first.method)
	require.JSONEq(t, `{"name":"Acme"}`, string(first.body))
	require.Equal(t, first.body, second.body, "the retry must send the same bytes")
	key := first.header.Get("Idempotency-Key")
	require.NotEmpty(t, key, "the SDK generates an idempotency key for a POST")
	require.Equal(t, key, second.header.Get("Idempotency-Key"))
}

// failingOnce fails its first round trip the way a refused connection does
// and passes every later request through.
type failingOnce struct {
	failed atomic.Bool
	base   http.RoundTripper
}

func (f *failingOnce) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.failed.CompareAndSwap(false, true) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errors.New("dial tcp: connect: connection refused")
	}
	return f.base.RoundTrip(req)
}

// sleepRecorder is the injected sleeper: it records each wait and returns at
// once.
type sleepRecorder struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (s *sleepRecorder) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waits = append(s.waits, d)
	return nil
}

func (s *sleepRecorder) recorded() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.waits...)
}

func TestWIF_14_ExchangeRetries(t *testing.T) {
	t.Run("503 then 429 then 200", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, n int, w http.ResponseWriter) {
			switch n {
			case 1:
				writeJSON(w, http.StatusServiceUnavailable, `{"message":"Service Unavailable"}`)
			case 2:
				w.Header().Set("Retry-After", "0")
				writeJSON(w, http.StatusTooManyRequests, `{"message":"Too Many Requests"}`)
			default:
				e.succeed(w)
			}
		})
		api := newAPIMock(t, nil)
		var providerCalls atomic.Int32
		creds := newTestCredentials(t, endpoint, assertion("assertion-1", &providerCalls))

		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		require.Equal(t, 3, endpoint.count(), "exchange count")
		require.Equal(t, int32(3), providerCalls.Load(), "provider count")
		require.Equal(t, []string{"Bearer access-1"}, api.authorizations())
	})

	t.Run("connection failure then 200", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, nil)
		api := newAPIMock(t, nil)
		var providerCalls atomic.Int32
		creds := newTestCredentials(t, endpoint, assertion("assertion-1", &providerCalls), func(cfg *WorkloadIdentityConfig) {
			cfg.HTTPClient = &http.Client{Transport: &failingOnce{base: http.DefaultTransport}}
		})

		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		require.Equal(t, int32(2), providerCalls.Load(), "provider count")
		require.Equal(t, 1, endpoint.count(), "only the second attempt reaches the endpoint")
	})

	t.Run("provider failure then success", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, nil)
		api := newAPIMock(t, nil)
		var providerCalls atomic.Int32
		creds := newTestCredentials(t, endpoint, func(context.Context) (string, error) {
			if providerCalls.Add(1) == 1 {
				return "", errors.New("the identity service is not ready")
			}
			return "assertion-2", nil
		})

		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		require.Equal(t, int32(2), providerCalls.Load(), "provider count")
		require.Equal(t, 1, endpoint.count(), "exchange count")
		require.Equal(t, "assertion-2", endpoint.exchange(1).form.Get("assertion"))
	})

	t.Run("Retry-After is honored", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, n int, w http.ResponseWriter) {
			if n == 1 {
				w.Header().Set("Retry-After", "1")
				writeJSON(w, http.StatusTooManyRequests, `{"message":"Too Many Requests"}`)
				return
			}
			e.succeed(w)
		})
		api := newAPIMock(t, nil)
		creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
		sleeper := &sleepRecorder{}
		creds.sleep = sleeper.sleep

		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		require.Equal(t, 2, endpoint.count(), "exchange count")
		waits := sleeper.recorded()
		require.Len(t, waits, 1, "one wait, before the second attempt")
		require.GreaterOrEqual(t, waits[0], time.Second)
	})
}

func TestWIF_15_OAuthErrorIsTypedAndNotRetried(t *testing.T) {
	codes := []string{"invalid_grant", "invalid_target", "invalid_client", "unauthorized_client", "invalid_scope", "invalid_request"}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			description := "The server's description of " + code + "."
			endpoint := newTokenEndpoint(t, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
				writeOAuthError(w, code, description)
			})
			api := newAPIMock(t, nil)
			creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

			err := getOrganization(newWIFClient(creds, api))

			wifErr := requireWIFError(t, err, code)
			require.Equal(t, description, wifErr.Description)
			require.Equal(t, 1, endpoint.count(), "exchange count")
			require.Zero(t, api.count(), "no API request is sent without a token")
		})
	}
}

func TestWIF_16_FailedExchangeIsNotCached(t *testing.T) {
	endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, n int, w http.ResponseWriter) {
		if n == 1 {
			writeOAuthError(w, "invalid_grant", "No trust rule matched.")
			return
		}
		e.succeed(w)
	})
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	client := newWIFClient(creds, api)

	requireWIFError(t, getOrganization(client), "invalid_grant")
	require.NoError(t, getOrganization(client))

	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, []string{"Bearer access-1"}, api.authorizations())
}

// captureLogger records every line the SDK logs.
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *captureLogger) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func TestWIF_17_TokensNeverAppearInErrorsOrLogs(t *testing.T) {
	const (
		secretAssertion = "SECRET-ASSERTION-VALUE"
		secretAccess    = "SECRET-ACCESS-VALUE"
	)
	logger := &captureLogger{}

	// fail runs one request that must fail and returns its error.
	fail := func(provider IdentityTokenProvider, respond func(*tokenEndpoint, int, http.ResponseWriter), respondAPI func(int, http.ResponseWriter, *http.Request)) error {
		endpoint := newTokenEndpoint(t, respond)
		creds := newTestCredentials(t, endpoint, provider)
		err := getOrganization(newWIFClient(creds, newAPIMock(t, respondAPI), WithLogger(logger)))
		require.Error(t, err)
		return err
	}
	secretProvider := assertion(secretAssertion, nil)

	failures := map[string]error{
		"an invalid_grant exchange": fail(secretProvider, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
			writeOAuthError(w, "invalid_grant", "No trust rule matched.")
		}, nil),
		"a 500 until the retries run out": fail(secretProvider, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
			writeJSON(w, http.StatusInternalServerError, `{"message":"Internal Server Error"}`)
		}, nil),
		"a provider that fails": fail(func(context.Context) (string, error) {
			return "", errors.New("the identity service is unavailable")
		}, nil, nil),
		"a second 401 from the API": fail(secretProvider, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, `{"access_token":"`+secretAccess+`","token_type":"Bearer","expires_in":300}`)
		}, func(_ int, w http.ResponseWriter, _ *http.Request) {
			writeUnauthorized(w)
		}),
	}

	requireNoSecret := func(where, text string) {
		t.Helper()
		require.NotContains(t, text, secretAssertion, where)
		require.NotContains(t, text, secretAccess, where)
	}
	for name, failure := range failures {
		// Every error in the chain, in its message and its debug forms.
		for err := failure; err != nil; err = errors.Unwrap(err) {
			requireNoSecret(name, err.Error())
			requireNoSecret(name, fmt.Sprintf("%v", err))
			requireNoSecret(name, fmt.Sprintf("%+v", err))
			requireNoSecret(name, fmt.Sprintf("%#v", err))
		}
	}
	lines := logger.recorded()
	require.NotEmpty(t, lines, "the logger must have been used")
	for _, line := range lines {
		requireNoSecret("log line", line)
	}
}

func TestWIF_18_ExchangeDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		writeJSON(w, http.StatusOK, `{"access_token":"access-from-redirect","token_type":"Bearer","expires_in":300}`)
	}))
	t.Cleanup(target.Close)
	endpoint := newTokenEndpoint(t, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
		w.Header().Set("Location", target.URL+"/oauth2/token")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	err := getOrganization(newWIFClient(creds, api))

	requireWIFError(t, err, "exchange_failed")
	require.Zero(t, redirected.Load(), "the redirect target must receive no request")
	require.Equal(t, 1, endpoint.count(), "exchange count")
	require.Zero(t, api.count())
}

// In Go the credentials entry point is a separate constructor that takes no
// API key, so a key and credentials cannot both be passed. The case asserts
// that property, and that a client built with it never sends a static key.
func TestWIF_19_CredentialsConstructorTakesNoAPIKey(t *testing.T) {
	constructor := reflect.TypeOf(NewClientWithCredentials)
	require.Equal(t, 2, constructor.NumIn())
	require.Equal(t, reflect.TypeFor[Credentials](), constructor.In(0))
	require.True(t, constructor.IsVariadic())
	require.Equal(t, reflect.TypeFor[[]ClientOption](), constructor.In(1))

	t.Setenv("WORKOS_API_KEY", "sk_test_env")
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	client := newWIFClient(creds, api)
	require.Empty(t, client.apiKey)

	require.NoError(t, getOrganization(client))
	// An Authorization header the caller adds is replaced, not sent alongside.
	_, err := client.Organizations().Get(context.Background(), "org_01",
		WithExtraHeaders(http.Header{"Authorization": {"Bearer sk_test_static"}}))
	require.NoError(t, err)

	require.Equal(t, 2, api.count())
	for n := 1; n <= api.count(); n++ {
		require.Equal(t, []string{"Bearer access-1"}, api.request(n).header.Values("Authorization"))
	}
}

func TestWIF_20_CredentialsNeverFallBackToEnvironmentKey(t *testing.T) {
	t.Setenv("WORKOS_API_KEY", "sk_test_env")
	requireNoEnvironmentKey := func(t *testing.T, api *apiMock) {
		t.Helper()
		for _, authorization := range api.authorizations() {
			require.NotContains(t, authorization, "sk_test_env")
		}
	}

	t.Run("valid credentials are used", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, nil)
		api := newAPIMock(t, nil)
		creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		require.Equal(t, []string{"Bearer access-1"}, api.authorizations())
		requireNoEnvironmentKey(t, api)
	})

	t.Run("credentials with no token URL are an error", func(t *testing.T) {
		clearWIFEnv(t)

		creds, err := NewWorkloadIdentityCredentials(WorkloadIdentityConfig{
			ClientID:              wifClientID,
			EnvironmentID:         wifEnvironmentID,
			IdentityTokenProvider: assertion("assertion-1", nil),
		})

		require.Nil(t, creds)
		wifErr := requireWIFError(t, err, "invalid_configuration")
		require.Contains(t, wifErr.Description, "WORKOS_WIF_TOKEN_URL")
	})

	t.Run("a failed exchange is an error", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
			writeOAuthError(w, "invalid_client", "Unknown client.")
		})
		api := newAPIMock(t, nil)
		creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

		err := getOrganization(newWIFClient(creds, api))

		requireWIFError(t, err, "invalid_client")
		require.Zero(t, api.count(), "the request must not be sent with the environment key instead")
		requireNoEnvironmentKey(t, api)
	})
}

func TestWIF_21_TokenFileIsReadOnEveryExchange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-token")
	require.NoError(t, os.WriteFile(path, []byte("assertion-1\n"), 0o600))
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, TokenFileProvider(path))
	clock := newFakeClock(creds)
	client := newWIFClient(creds, api)

	require.NoError(t, getOrganization(client))

	require.NoError(t, os.WriteFile(path, []byte("  assertion-2\n"), 0o600))
	clock.at(241 * time.Second) // past the refresh threshold, which forces a second exchange
	require.NoError(t, getOrganization(client))

	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, "assertion-1", endpoint.exchange(1).form.Get("assertion"))
	require.Equal(t, "assertion-2", endpoint.exchange(2).form.Get("assertion"))
}

func TestWIF_22_ProvidersAndEnvironmentDefaults(t *testing.T) {
	t.Run("token from an environment variable", func(t *testing.T) {
		t.Setenv("MY_JWT", "assertion-env")
		endpoint := newTokenEndpoint(t, nil)
		creds := newTestCredentials(t, endpoint, TokenEnvProvider("MY_JWT"))

		require.NoError(t, getOrganization(newWIFClient(creds, newAPIMock(t, nil))))

		require.Equal(t, "assertion-env", endpoint.exchange(1).form.Get("assertion"))
	})

	t.Run("token from a callback", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, nil)
		creds := newTestCredentials(t, endpoint, func(context.Context) (string, error) {
			return "assertion-cb", nil
		})

		require.NoError(t, getOrganization(newWIFClient(creds, newAPIMock(t, nil))))

		require.Equal(t, "assertion-cb", endpoint.exchange(1).form.Get("assertion"))
	})

	setEnvironment := func(t *testing.T, endpoint *tokenEndpoint) {
		t.Helper()
		t.Setenv("WORKOS_CLIENT_ID", "client_env")
		t.Setenv("WORKOS_WIF_TOKEN_URL", endpoint.url())
		t.Setenv("WORKOS_WIF_SCOPE", "scope_env")
		t.Setenv("WORKOS_ENVIRONMENT_ID", "environment_env")
	}

	t.Run("omitted fields default from the environment", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, nil)
		api := newAPIMock(t, nil)
		setEnvironment(t, endpoint)

		creds, err := NewWorkloadIdentityCredentials(WorkloadIdentityConfig{
			IdentityTokenProvider: assertion("assertion-1", nil),
		})
		require.NoError(t, err)
		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		require.Equal(t, 1, endpoint.count(), "the POST must go to WORKOS_WIF_TOKEN_URL")
		form := endpoint.exchange(1).form
		require.Equal(t, "client_env", form.Get("client_id"))
		require.Equal(t, "scope_env", form.Get("scope"))
		require.Equal(t, "environment_env", api.request(1).header.Get("x-url-environment-id"))
	})

	t.Run("explicit values win over the environment", func(t *testing.T) {
		endpoint := newTokenEndpoint(t, nil)
		api := newAPIMock(t, nil)
		setEnvironment(t, endpoint)

		creds, err := NewWorkloadIdentityCredentials(WorkloadIdentityConfig{
			ClientID:              "client_explicit",
			Scope:                 "scope_explicit",
			EnvironmentID:         "environment_explicit",
			IdentityTokenProvider: assertion("assertion-1", nil),
		})
		require.NoError(t, err)
		require.NoError(t, getOrganization(newWIFClient(creds, api)))

		form := endpoint.exchange(1).form
		require.Equal(t, "client_explicit", form.Get("client_id"))
		require.Equal(t, "scope_explicit", form.Get("scope"))
		require.Equal(t, "environment_explicit", api.request(1).header.Get("x-url-environment-id"))
	})
}

func TestWIF_23_CanceledWaiterDoesNotCancelSharedExchange(t *testing.T) {
	held := newGate()
	defer held.open()
	received := make(chan struct{}, 1)
	endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, _ int, w http.ResponseWriter) {
		received <- struct{}{}
		held.wait()
		e.succeed(w)
	})
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	entered := make(chan struct{}, 8)
	client := newWIFClient(announcingCredentials{creds, func() { entered <- struct{}{} }}, api)

	// Caller A starts the exchange, so it is A's context that must not own it.
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	resultA := make(chan error, 1)
	go func() {
		_, err := client.Organizations().Get(ctxA, "org_01")
		resultA <- err
	}()
	receive(t, entered, "caller A to reach the credentials")
	receive(t, received, "the token endpoint to receive the exchange")

	// Caller B joins the exchange A started.
	resultB := make(chan error, 1)
	go func() { resultB <- getOrganization(client) }()
	receive(t, entered, "caller B to reach the credentials")

	cancelA()
	require.ErrorIs(t, receive(t, resultA, "caller A to give up"), context.Canceled)

	held.open()
	require.NoError(t, receive(t, resultB, "caller B to finish"))
	require.Equal(t, 1, endpoint.count(), "exchange count")
	require.Equal(t, []string{"Bearer access-1"}, api.authorizations())
}

func TestWIF_24_StaticAPIKeyClientIsUnchanged(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 2 {
			writeUnauthorized(w)
			return
		}
		writeOrganization(w)
	})
	client := NewClient("sk_test_static", WithBaseURL(api.server.URL))

	require.NoError(t, getOrganization(client))
	header := api.request(1).header
	require.Equal(t, []string{"Bearer sk_test_static"}, header.Values("Authorization"))
	require.Empty(t, header.Values("x-url-environment-id"))

	err := getOrganization(client)
	var authErr *AuthenticationError
	require.ErrorAs(t, err, &authErr)
	require.Equal(t, 2, api.count(), "the 401 is returned after exactly one attempt")
	require.Zero(t, endpoint.count(), "exchange count")
}

func TestWIFExtra_UnreplayableBodyReturnsThe401(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeUnauthorized(w)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	transport := &credentialsTransport{base: http.DefaultTransport, credentials: creds}

	// A body with no GetBody cannot be sent a second time.
	req, err := http.NewRequest(http.MethodPost, api.server.URL, io.NopCloser(strings.NewReader(`{"name":"Acme"}`)))
	require.NoError(t, err)
	require.Nil(t, req.GetBody)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, 1, api.count(), "API attempts")
	require.Equal(t, 1, endpoint.count(), "exchange count")
}

// Outside request() the context carries no recovery allowance; the transport
// then allows one recovery for that call.
func TestWIFExtra_TransportRecoversOnceWithoutRequestState(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeUnauthorized(w)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	transport := &credentialsTransport{base: http.DefaultTransport, credentials: creds}

	req, err := http.NewRequest(http.MethodGet, api.server.URL, nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, []string{"Bearer access-1", "Bearer access-2"}, api.authorizations())
	require.Empty(t, req.Header.Values("Authorization"), "the caller's request must not be modified")
}

// fixedCredentials is a caller's own Credentials. It returns the same headers
// every time and records how it was called.
type fixedCredentials struct {
	recoverable bool

	mu          sync.Mutex
	resolves    int
	invalidated []uint64
}

func (c *fixedCredentials) Resolve(context.Context) (CredentialSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resolves++
	headers := make(http.Header, 1)
	headers.Set("Authorization", "Bearer fixed-key")
	return CredentialSnapshot{Headers: headers, Generation: 7, Recoverable: c.recoverable}, nil
}

func (c *fixedCredentials) Invalidate(generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidated = append(c.invalidated, generation)
}

func (c *fixedCredentials) calls() (resolves int, invalidated []uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resolves, c.invalidated
}

// Only a snapshot marked Recoverable earns the second attempt. For
// credentials that cannot change, resolving again would send the same
// rejected headers.
func TestWIFExtra_OnlyRecoverableSnapshotsAreRetriedAfterA401(t *testing.T) {
	for _, tc := range []struct {
		name        string
		recoverable bool
		attempts    int
		resolves    int
		invalidated []uint64
	}{
		{name: "not recoverable", recoverable: false, attempts: 1, resolves: 1},
		{name: "recoverable", recoverable: true, attempts: 2, resolves: 2, invalidated: []uint64{7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newAPIMock(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				writeUnauthorized(w)
			})
			creds := &fixedCredentials{recoverable: tc.recoverable}

			err := getOrganization(newWIFClient(creds, api))

			var authErr *AuthenticationError
			require.ErrorAs(t, err, &authErr)
			require.Equal(t, http.StatusUnauthorized, authErr.StatusCode)
			require.Equal(t, tc.attempts, api.count(), "API attempts")
			resolves, invalidated := creds.calls()
			require.Equal(t, tc.resolves, resolves, "Resolve calls")
			require.Equal(t, tc.invalidated, invalidated, "Invalidate calls")
		})
	}
}

func TestWIFExtra_CredentialsStayOnTheOriginTheyWereSentTo(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	var api *apiMock
	// The other origin sends the request back to a URL of its choosing.
	elsewhere := newAPIMock(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, api.server.URL+"/chosen-elsewhere", http.StatusTemporaryRedirect)
	})
	api = newAPIMock(t, func(n int, w http.ResponseWriter, r *http.Request) {
		switch n {
		case 1:
			http.Redirect(w, r, "/moved", http.StatusTemporaryRedirect)
		case 2:
			http.Redirect(w, r, elsewhere.server.URL+"/elsewhere", http.StatusTemporaryRedirect)
		default:
			writeOrganization(w)
		}
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	require.NoError(t, getOrganization(newWIFClient(creds, api)))

	require.Equal(t, 1, elsewhere.count())
	header := elsewhere.request(1).header
	require.Empty(t, header.Values("Authorization"), "the token must not follow a redirect to another origin")
	require.Empty(t, header.Values("x-url-environment-id"))

	require.Equal(t, 3, api.count())
	require.Equal(t, []string{"Bearer access-1", "Bearer access-1", ""}, api.authorizations(),
		"a redirect within the origin keeps the credentials; one that comes back from another origin does not get them again")
	require.Equal(t, "/chosen-elsewhere", api.request(3).path)
	require.Empty(t, api.request(3).header.Values("x-url-environment-id"))
}

// countingTransport counts the requests that pass through it.
type countingTransport struct {
	calls atomic.Int32
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return http.DefaultTransport.RoundTrip(req)
}

func TestWIFExtra_WithHTTPClientIsWrappedNotReplaced(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	counting := &countingTransport{}
	custom := &http.Client{Transport: counting, Timeout: 5 * time.Second}

	client := newWIFClient(creds, api, WithHTTPClient(custom))
	require.NoError(t, getOrganization(client))

	require.Equal(t, int32(1), counting.calls.Load(), "the request must go through the caller's transport")
	require.Equal(t, []string{"Bearer access-1"}, api.authorizations())
	require.Same(t, counting, custom.Transport, "the caller's client must not be modified")
	require.Equal(t, 5*time.Second, client.httpClient.Timeout)
}

func TestWIFExtra_NilCredentialsFailWithoutARequest(t *testing.T) {
	api := newAPIMock(t, nil)
	var nilPointer *WorkloadIdentityCredentials
	nilPointer.Invalidate(1) // must not panic

	cases := map[string]Credentials{
		"nil interface": nil,
		"nil pointer":   nilPointer,
		"zero value":    &WorkloadIdentityCredentials{},
	}
	for name, creds := range cases {
		t.Run(name, func(t *testing.T) {
			requireWIFError(t, getOrganization(newWIFClient(creds, api)), "invalid_configuration")
		})
	}
	require.Zero(t, api.count())
}

func TestWIFExtra_ExchangeResponses(t *testing.T) {
	everyAttempt := defaultMaxRetries + 1
	cases := []struct {
		name      string
		status    int
		body      string
		code      string
		exchanges int
	}{
		{"200 that is not JSON", http.StatusOK, "not json", "invalid_response", 1},
		{"200 with no access_token", http.StatusOK, `{"token_type":"Bearer"}`, "invalid_response", 1},
		{"200 with an empty access_token", http.StatusOK, `{"access_token":""}`, "invalid_response", 1},
		{"200 with an OAuth error", http.StatusOK, `{"error":"invalid_grant"}`, "invalid_grant", 1},
		{"403 with no OAuth error", http.StatusForbidden, `{"message":"Forbidden"}`, "invalid_response", 1},
		{"500 until the retries run out", http.StatusInternalServerError, "upstream failure", "exchange_failed", everyAttempt},
		{"501, which the request path does not retry", http.StatusNotImplemented, "", "exchange_failed", everyAttempt},
		{"503 with an OAuth error until the retries run out", http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, "temporarily_unavailable", everyAttempt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
				writeJSON(w, tc.status, tc.body)
			})
			creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

			_, err := creds.Resolve(context.Background())

			requireWIFError(t, err, tc.code)
			require.Equal(t, tc.exchanges, endpoint.count(), "exchange count")
		})
	}
}

func TestWIFExtra_UnknownOAuthCodeGetsTheGeneralHint(t *testing.T) {
	endpoint := newTokenEndpoint(t, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
		writeJSON(w, http.StatusBadRequest, `{"error":"access_denied"}`)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	_, err := creds.Resolve(context.Background())

	wifErr := requireWIFError(t, err, "access_denied")
	require.Equal(t, "The token endpoint rejected the exchange.", wifErr.Hint)
	require.Empty(t, wifErr.Description)
	require.Equal(t, "workos: access_denied: The token endpoint rejected the exchange.", err.Error())
}

func TestWIFExtra_UnusableExpiresInMeans300Seconds(t *testing.T) {
	for _, expiresIn := range []string{`"300"`, `0`, `-5`, `null`, `[]`} {
		t.Run(expiresIn, func(t *testing.T) {
			endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, _ int, w http.ResponseWriter) {
				writeJSON(w, http.StatusOK, fmt.Sprintf(`{"access_token":%q,"expires_in":%s}`, e.nextToken(), expiresIn))
			})
			creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

			_, err := creds.Resolve(context.Background())
			require.NoError(t, err)

			creds.mu.Lock()
			defer creds.mu.Unlock()
			require.Equal(t, 300*time.Second, creds.lifetime)
		})
	}
}

func TestWIFExtra_DescriptionIsCutAndNeverEchoesTheAssertion(t *testing.T) {
	const secretAssertion = "SECRET-ASSERTION-VALUE"
	endpoint := newTokenEndpoint(t, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
		writeOAuthError(w, "invalid_grant", "rejected "+secretAssertion+" "+strings.Repeat("é", 600))
	})
	creds := newTestCredentials(t, endpoint, assertion(secretAssertion, nil))

	_, err := creds.Resolve(context.Background())

	wifErr := requireWIFError(t, err, "invalid_grant")
	require.Equal(t, 500, len([]rune(wifErr.Description)), "the description is cut to 500 characters")
	require.True(t, strings.HasPrefix(wifErr.Description, "rejected [redacted] é"))
	require.NotContains(t, err.Error(), secretAssertion)
}

func TestWIFExtra_ProviderFailuresLeaveNothingBehind(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	var calls atomic.Int32
	creds := newTestCredentials(t, endpoint, func(context.Context) (string, error) {
		switch n := calls.Add(1); {
		case n <= int32(defaultMaxRetries)+1:
			panic("boom") // every attempt of the first exchange
		case n <= 2*(int32(defaultMaxRetries)+1):
			return "", nil // every attempt of the second
		default:
			return "assertion-1", nil
		}
	})
	ctx := context.Background()

	_, err := creds.Resolve(ctx)
	wifErr := requireWIFError(t, err, "provider_failed")
	require.Contains(t, wifErr.Description, "boom", "a panic in the provider is reported, not raised")

	_, err = creds.Resolve(ctx)
	wifErr = requireWIFError(t, err, "provider_failed")
	require.Contains(t, wifErr.Description, "empty token")
	require.Zero(t, endpoint.count(), "nothing is exchanged without an assertion")

	snapshot, err := creds.Resolve(ctx)
	require.NoError(t, err)
	require.Equal(t, "Bearer access-1", snapshot.Headers.Get("Authorization"))
}

func TestWIFExtra_ExchangeStopsRetryingAtItsDeadline(t *testing.T) {
	endpoint := newTokenEndpoint(t, func(_ *tokenEndpoint, _ int, w http.ResponseWriter) {
		writeJSON(w, http.StatusInternalServerError, `{"message":"Internal Server Error"}`)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))
	// The sleeper reports that the exchange deadline passed during the wait.
	creds.sleep = func(context.Context, time.Duration) error { return context.DeadlineExceeded }

	_, err := creds.Resolve(context.Background())

	requireWIFError(t, err, "exchange_failed")
	require.Equal(t, 1, endpoint.count(), "exchange count")
}

func TestWIFExtra_ConfigurationIsValidatedAtConstruction(t *testing.T) {
	clearWIFEnv(t)
	valid := func() WorkloadIdentityConfig {
		return WorkloadIdentityConfig{
			ClientID:              wifClientID,
			TokenURL:              "https://auth.example.com/oauth2/token",
			EnvironmentID:         wifEnvironmentID,
			IdentityTokenProvider: assertion("assertion-1", nil),
		}
	}
	_, err := NewWorkloadIdentityCredentials(valid())
	require.NoError(t, err)

	cases := []struct {
		name        string
		invalidate  func(*WorkloadIdentityConfig)
		description string
	}{
		{"no client ID", func(cfg *WorkloadIdentityConfig) { cfg.ClientID = "" }, "ClientID is required (or set WORKOS_CLIENT_ID)"},
		{"no token URL", func(cfg *WorkloadIdentityConfig) { cfg.TokenURL = "" }, "TokenURL is required (or set WORKOS_WIF_TOKEN_URL)"},
		{"no environment ID", func(cfg *WorkloadIdentityConfig) { cfg.EnvironmentID = "" }, "EnvironmentID is required (or set WORKOS_ENVIRONMENT_ID)"},
		{"no provider", func(cfg *WorkloadIdentityConfig) { cfg.IdentityTokenProvider = nil }, "IdentityTokenProvider is required"},
		{"a token URL with no scheme", func(cfg *WorkloadIdentityConfig) { cfg.TokenURL = "auth.example.com/oauth2/token" }, "TokenURL must be an absolute http or https URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.invalidate(&cfg)

			creds, err := NewWorkloadIdentityCredentials(cfg)

			require.Nil(t, creds)
			wifErr := requireWIFError(t, err, "invalid_configuration")
			require.Equal(t, tc.description, wifErr.Description)
		})
	}
}

func TestWIFExtra_TokenProvidersRejectMissingTokens(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, []byte(" \n"), 0o600))
	_, err := TokenFileProvider(empty)(ctx)
	require.ErrorContains(t, err, "is empty")

	_, err = TokenFileProvider(filepath.Join(dir, "missing"))(ctx)
	require.ErrorIs(t, err, os.ErrNotExist)

	t.Setenv("WIF_TEST_UNSET_TOKEN", "")
	_, err = TokenEnvProvider("WIF_TEST_UNSET_TOKEN")(ctx)
	require.ErrorContains(t, err, "WIF_TEST_UNSET_TOKEN")
}

// A provider that ignores its context and blocks must not hold the shared
// exchange open past its deadline, or every later request would join it.
func TestWIFExtra_BlockedProviderIsAbandonedAtTheDeadline(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	blocked := make(chan struct{})
	defer close(blocked)
	var calls atomic.Int32
	creds := newTestCredentials(t, endpoint, func(context.Context) (string, error) {
		if calls.Add(1) == 1 {
			<-blocked
		}
		return "assertion-1", nil
	})
	creds.deadline = 50 * time.Millisecond
	// The caller waits far longer than the exchange deadline, so a failure
	// here is the exchange giving up, not the caller.
	ctx, cancel := context.WithTimeout(context.Background(), wifWaitLimit)
	defer cancel()

	_, err := creds.Resolve(ctx)

	wifErr := requireWIFError(t, err, "provider_failed")
	require.ErrorIs(t, wifErr, context.DeadlineExceeded)
	require.Zero(t, endpoint.count(), "exchange count")

	// Nothing of the stuck call is left: the next request exchanges anew.
	creds.deadline = workloadIdentityExchangeDeadline
	snapshot, err := creds.Resolve(ctx)
	require.NoError(t, err)
	require.Equal(t, "Bearer access-1", snapshot.Headers.Get("Authorization"))
	require.Equal(t, 1, endpoint.count(), "exchange count")
}

// request() copies the HTTP client to apply a per-request timeout. The copy
// must keep the credentials transport.
func TestWIFExtra_PerRequestTimeoutKeepsCredentials(t *testing.T) {
	endpoint := newTokenEndpoint(t, nil)
	api := newAPIMock(t, nil)
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	_, err := newWIFClient(creds, api).Organizations().Get(context.Background(), "org_01", WithTimeout(5*time.Second))
	require.NoError(t, err)

	header := api.request(1).header
	require.Equal(t, []string{"Bearer access-1"}, header.Values("Authorization"))
	require.Equal(t, []string{"environment_wif_test"}, header.Values("x-url-environment-id"))
}

// When the exchange after a 401 fails, the caller gets that failure, which
// says why there is no token, and not the 401.
func TestWIFExtra_FailedExchangeDuringRecoveryIsReturned(t *testing.T) {
	endpoint := newTokenEndpoint(t, func(e *tokenEndpoint, n int, w http.ResponseWriter) {
		if n == 1 {
			e.succeed(w)
			return
		}
		writeOAuthError(w, "invalid_grant", "The identity token has expired.")
	})
	api := newAPIMock(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeUnauthorized(w)
	})
	creds := newTestCredentials(t, endpoint, assertion("assertion-1", nil))

	err := getOrganization(newWIFClient(creds, api))

	requireWIFError(t, err, "invalid_grant")
	require.Equal(t, 2, endpoint.count(), "exchange count")
	require.Equal(t, 1, api.count(), "API attempts")
}

// A client with no API key sends no Authorization header of its own, so a
// credentials client cannot send "Bearer " with no token where its transport
// does not run.
func TestWIFExtra_ClientWithoutAPIKeySendsNoAuthorizationHeader(t *testing.T) {
	api := newAPIMock(t, nil)

	require.NoError(t, getOrganization(NewClient("", WithBaseURL(api.server.URL))))

	_, sent := api.request(1).header["Authorization"]
	require.False(t, sent)
}
