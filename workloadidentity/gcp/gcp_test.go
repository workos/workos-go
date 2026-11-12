package gcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const testAudience = "https://api.workos.com"

// metadataServer is a mock of the metadata server that records the requests
// it receives. The provider is pointed at it for the length of the test.
type metadataServer struct {
	*httptest.Server
	requests atomic.Int32
	last     atomic.Pointer[http.Request]
}

func newMetadataServer(t *testing.T, respond http.HandlerFunc) *metadataServer {
	t.Helper()
	s := &metadataServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.last.Store(r)
		respond(w, r)
	}))
	t.Cleanup(s.Close)

	original := metadataBaseURL
	metadataBaseURL = s.URL
	t.Cleanup(func() { metadataBaseURL = original })
	return s
}

func TestWIF_GCP_01_RequestsIdentityTokenForAudience(t *testing.T) {
	server := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("gcp-jwt\n"))
	})

	token, err := New(testAudience)(context.Background())
	if err != nil {
		t.Fatalf("provider failed: %v", err)
	}

	if token != "gcp-jwt" {
		t.Errorf("token = %q, want %q", token, "gcp-jwt")
	}
	if got := server.requests.Load(); got != 1 {
		t.Fatalf("the mock received %d requests, want 1", got)
	}
	req := server.last.Load()
	if req.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.Method)
	}
	if want := "/computeMetadata/v1/instance/service-accounts/default/identity"; req.URL.Path != want {
		t.Errorf("path = %q, want %q", req.URL.Path, want)
	}
	if want := "audience=https%3A%2F%2Fapi.workos.com&format=full"; req.URL.RawQuery != want {
		t.Errorf("query = %q, want %q", req.URL.RawQuery, want)
	}
	if got := req.Header.Get("Metadata-Flavor"); got != "Google" {
		t.Errorf("Metadata-Flavor = %q, want Google", got)
	}
}

func TestWIF_GCP_02_BadResponseIsAnError(t *testing.T) {
	const secret = "SECRET-JWT-VALUE"
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		_, _ = w.Write([]byte(secret))
	}))
	t.Cleanup(target.Close)

	cases := []struct {
		name    string
		respond http.HandlerFunc
		want    string
	}{
		{"not found", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, secret, http.StatusNotFound)
		}, "HTTP 404"},
		{"empty body", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}, "no token"},
		{"blank body", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(" \n"))
		}, "no token"},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}, "HTTP 302"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newMetadataServer(t, tc.respond)

			_, err := New(testAudience)(context.Background())

			if err == nil {
				t.Fatal("the provider succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q contains a token", err)
			}
			if got := server.requests.Load(); got != 1 {
				t.Errorf("the mock received %d requests, want 1", got)
			}
		})
	}
	if got := redirected.Load(); got != 0 {
		t.Errorf("the redirect target received %d requests, want none", got)
	}
}

func TestAudienceIsEscaped(t *testing.T) {
	server := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("gcp-jwt"))
	})

	if _, err := New("urn:workos:api/v1?x=1&y=2")(context.Background()); err != nil {
		t.Fatalf("provider failed: %v", err)
	}

	req := server.last.Load()
	if got, want := req.URL.Query().Get("audience"), "urn:workos:api/v1?x=1&y=2"; got != want {
		t.Errorf("audience = %q, want %q", got, want)
	}
	if got := req.URL.Query().Get("format"); got != "full" {
		t.Errorf("format = %q, want full", got)
	}
}

func TestEmptyAudienceIsAnError(t *testing.T) {
	server := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("gcp-jwt"))
	})

	if _, err := New("")(context.Background()); err == nil {
		t.Fatal("the provider succeeded with no audience")
	}
	if got := server.requests.Load(); got != 0 {
		t.Errorf("the mock received %d requests, want none", got)
	}
}

func TestWIF_GCP_03_TheRequestNeverUsesAProxy(t *testing.T) {
	// A proxy from the environment cannot be tested through the mock: Go never
	// sends a request for a loopback address to it. So check the transport
	// itself. An http.Transport uses a proxy only when Proxy is set, and the
	// default transport, which a client without a transport falls back to,
	// sets it to http.ProxyFromEnvironment.
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the client's transport is %T, want a *http.Transport of its own", httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("the client's transport has a Proxy function; the metadata request must always go direct")
	}

	// The transport still reaches the metadata server.
	server := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("gcp-jwt"))
	})
	if token, err := New(testAudience)(context.Background()); err != nil || token != "gcp-jwt" {
		t.Fatalf("token = %q, err = %v; want gcp-jwt and no error", token, err)
	}
	if got := server.requests.Load(); got != 1 {
		t.Errorf("the mock received %d requests, want 1", got)
	}
}
