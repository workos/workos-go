package githubactions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

const testAudience = "https://api.workos.com"

// tokenServer is a mock of GitHub's OIDC token endpoint that records the
// requests it receives.
type tokenServer struct {
	*httptest.Server
	requests atomic.Int32
	last     atomic.Pointer[http.Request]
}

func newTokenServer(t *testing.T, respond http.HandlerFunc) *tokenServer {
	t.Helper()
	s := &tokenServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.last.Store(r)
		respond(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// setEnv sets the two variables GitHub Actions provides. An empty value
// leaves the variable unset; t.Setenv restores the original afterwards.
func setEnv(t *testing.T, requestURL, requestToken string) {
	t.Helper()
	for name, value := range map[string]string{requestURLEnv: requestURL, requestTokenEnv: requestToken} {
		t.Setenv(name, value)
		if value == "" {
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestWIF_GHA_01_RequestsTokenForAudience(t *testing.T) {
	server := newTokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value": "gha-jwt"}`))
	})
	setEnv(t, server.URL+"/token?api-version=2.0", "gha-request-token")

	token, err := New(testAudience)(context.Background())
	if err != nil {
		t.Fatalf("provider failed: %v", err)
	}

	if token != "gha-jwt" {
		t.Errorf("token = %q, want %q", token, "gha-jwt")
	}
	if got := server.requests.Load(); got != 1 {
		t.Fatalf("the mock received %d requests, want 1", got)
	}
	req := server.last.Load()
	if req.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.Method)
	}
	if req.URL.Path != "/token" {
		t.Errorf("path = %q, want /token", req.URL.Path)
	}
	if want := "api-version=2.0&audience=https%3A%2F%2Fapi.workos.com"; req.URL.RawQuery != want {
		t.Errorf("query = %q, want %q", req.URL.RawQuery, want)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer gha-request-token" {
		t.Errorf("Authorization = %q, want the request token as a bearer", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want application/json", got)
	}
}

func TestWIF_GHA_02_MissingEnvFailsWithPermissionHint(t *testing.T) {
	server := newTokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value": "gha-jwt"}`))
	})
	cases := []struct {
		name         string
		requestURL   string
		requestToken string
	}{
		{"no request URL", "", "gha-request-token"},
		{"no request token", server.URL + "/token?api-version=2.0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.requestURL, tc.requestToken)

			_, err := New(testAudience)(context.Background())

			if err == nil {
				t.Fatal("the provider succeeded without its environment")
			}
			if !strings.Contains(err.Error(), "permissions: id-token: write") {
				t.Errorf("error %q does not say to add the permission", err)
			}
		})
	}
	if got := server.requests.Load(); got != 0 {
		t.Errorf("the mock received %d requests, want none", got)
	}
}

func TestProviderReadsEnvironmentOnEveryCall(t *testing.T) {
	server := newTokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value": "gha-jwt"}`))
	})
	provider := New(testAudience) // built before the environment is set
	setEnv(t, server.URL+"/token", "gha-request-token")

	if _, err := provider(context.Background()); err != nil {
		t.Fatalf("provider failed: %v", err)
	}
	// A request URL with no query string gets one.
	if got, want := server.last.Load().URL.RawQuery, "audience=https%3A%2F%2Fapi.workos.com"; got != want {
		t.Errorf("query = %q, want %q", got, want)
	}
}

func TestProviderFailures(t *testing.T) {
	const secret = "SECRET-JWT-VALUE"
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		_, _ = w.Write([]byte(`{"value": "` + secret + `"}`))
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
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}, "HTTP 302"},
		{"not JSON", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(secret))
		}, "not JSON"},
		{"no value", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"count": 1}`))
		}, "no token"},
		{"empty value", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"value": ""}`))
		}, "no token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newTokenServer(t, tc.respond)
			setEnv(t, server.URL+"/token?api-version=2.0", "gha-request-token")

			_, err := New(testAudience)(context.Background())

			if err == nil {
				t.Fatal("the provider succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "gha-request-token") {
				t.Errorf("error %q contains a token", err)
			}
		})
	}
	if got := redirected.Load(); got != 0 {
		t.Errorf("the redirect target received %d requests, want none", got)
	}
}

func TestEmptyAudienceIsAnError(t *testing.T) {
	server := newTokenServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value": "gha-jwt"}`))
	})
	setEnv(t, server.URL+"/token", "gha-request-token")

	if _, err := New("")(context.Background()); err == nil {
		t.Fatal("the provider succeeded with no audience")
	}
	if got := server.requests.Load(); got != 0 {
		t.Errorf("the mock received %d requests, want none", got)
	}
}
