// @oagen-ignore-file

package workos

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
)

// Credentials supplies authorization for each HTTP attempt.
//
// WorkloadIdentityCredentials is the implementation the SDK ships. A client
// built with NewClientWithCredentials calls Resolve before every attempt,
// including retries. When the API answers 401 to a snapshot that is
// Recoverable, the client calls Invalidate, resolves again and repeats the
// request once.
type Credentials interface {
	// Resolve returns the headers for one HTTP attempt. It may block while a
	// credential is fetched and must honor ctx. An error that is a
	// *WorkloadIdentityError fails the request without a retry.
	Resolve(ctx context.Context) (CredentialSnapshot, error)
	// Invalidate discards the cached credential only if it is still
	// the given generation. It must not block on the network.
	Invalidate(generation uint64)
}

// CredentialSnapshot is the authorization for one HTTP attempt.
type CredentialSnapshot struct {
	// Headers are set on the request, replacing any header of the same name:
	// Authorization and, when an environment ID is set, x-url-environment-id
	// for workload identity.
	Headers http.Header
	// Generation identifies the credential the headers came from. A 401 to a
	// Recoverable snapshot is reported back with it through
	// Credentials.Invalidate.
	Generation uint64
	// Recoverable reports whether a 401 answer to these headers is worth one
	// more attempt with newly resolved credentials. Set it when Resolve can
	// return a different credential after Invalidate, as workload identity
	// credentials do. Credentials that never change, such as a fixed key,
	// leave it false, and the 401 goes to the caller.
	Recoverable bool
}

// NewClientWithCredentials creates a client that authenticates with
// short-lived credentials instead of an API key.
//
//	creds, err := workos.NewWorkloadIdentityCredentials(workos.WorkloadIdentityConfig{
//		IdentityTokenProvider: workos.TokenFileProvider("/var/run/secrets/tokens/workos"),
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	client := workos.NewClientWithCredentials(creds)
//
// The client holds no API key and never sends one. When the API answers 401
// to recoverable credentials, as workload identity credentials are, the
// client discards the credential it sent, resolves a new one and repeats the
// request once.
//
// Requests that authenticate with the API key as a client secret, such as
// the UserManagement().AuthenticateWith... methods and
// SSO().GetProfileAndToken, need a client created with NewClient.
func NewClientWithCredentials(creds Credentials, opts ...ClientOption) *Client {
	c := NewClient("", opts...)

	// Wrap a copy, after the options ran: a client passed to WithHTTPClient
	// keeps its settings and is never modified.
	httpClient := http.Client{Timeout: defaultTimeout}
	if c.httpClient != nil {
		httpClient = *c.httpClient
	}
	base := httpClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	httpClient.Transport = &credentialsTransport{base: base, credentials: creds}
	c.httpClient = &httpClient
	return c
}

// credentialRecovery is the single 401-recovery allowance of one logical
// request. request() creates it before its retry loop and carries it on the
// context of every attempt, so the retries of one request cannot each earn a
// recovery of their own.
type credentialRecovery struct {
	used atomic.Bool
}

type credentialRecoveryKey struct{}

// withCredentialRecovery returns a context carrying a fresh allowance.
func withCredentialRecovery(ctx context.Context) context.Context {
	return context.WithValue(ctx, credentialRecoveryKey{}, &credentialRecovery{})
}

// credentialsTransport authorizes each request with a credential snapshot
// and recovers once from a 401. It follows the shape of the transport in
// golang.org/x/oauth2.
type credentialsTransport struct {
	base        http.RoundTripper
	credentials Credentials
}

func (t *credentialsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A RoundTripper must close the request body, even when it fails before
	// sending anything.
	bodyClosed := false
	if req.Body != nil {
		defer func() {
			if !bodyClosed {
				req.Body.Close()
			}
		}()
	}

	if t.credentials == nil {
		return nil, invalidWorkloadIdentityConfiguration("NewClientWithCredentials was called with nil credentials")
	}
	if redirectedOffOrigin(req) {
		bodyClosed = true
		return t.base.RoundTrip(req)
	}

	ctx := req.Context()
	snapshot, err := t.credentials.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	bodyClosed = true // from here on the base transport closes it
	resp, err := t.base.RoundTrip(authorized(req, snapshot))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	// The API rejected this credential. Discard it, resolve a new one and
	// send the same request once more. Without that chance, the 401 goes to
	// the caller as it is.
	if !snapshot.Recoverable {
		return resp, nil // resolving again would return the same credential
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	if hasBody && req.GetBody == nil {
		return resp, nil // the body cannot be replayed
	}
	if recovery, ok := ctx.Value(credentialRecoveryKey{}).(*credentialRecovery); ok && !recovery.used.CompareAndSwap(false, true) {
		return resp, nil // this logical request already recovered once
	}
	var body io.ReadCloser
	if hasBody {
		if body, err = req.GetBody(); err != nil {
			return resp, nil
		}
	}

	// Drain what is left of the 401 so its connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()

	t.credentials.Invalidate(snapshot.Generation)
	snapshot, err = t.credentials.Resolve(ctx)
	if err != nil {
		if body != nil {
			body.Close()
		}
		return nil, err
	}
	retry := authorized(req, snapshot)
	if body != nil {
		retry.Body = body
	}
	return t.base.RoundTrip(retry)
}

// authorized returns a copy of req carrying the snapshot's headers. The
// original is left untouched, as the RoundTripper contract requires, and a
// header of the same name already on the request is replaced.
func authorized(req *http.Request, snapshot CredentialSnapshot) *http.Request {
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	for name, values := range snapshot.Headers {
		clone.Header.Del(name)
		for _, value := range values {
			clone.Header.Add(name, value)
		}
	}
	return clone
}

// redirectedOffOrigin reports whether req follows a chain of redirects that
// left the origin the caller addressed. net/http drops a caller's
// Authorization header on such a hop and keeps it dropped for the rest of the
// chain, and the credentials are withheld the same way: an access token must
// not follow a redirect to another host, nor to a URL that another host
// chose, even one back on the first origin.
func redirectedOffOrigin(req *http.Request) bool {
	first := req
	for first.Response != nil {
		if first.Response.Request == nil {
			return true // the start of the chain is unknown
		}
		first = first.Response.Request
	}
	for hop := req; hop != first; hop = hop.Response.Request {
		if hop.URL.Scheme != first.URL.Scheme || hop.URL.Host != first.URL.Host {
			return true
		}
	}
	return false
}
