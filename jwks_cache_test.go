// @oagen-ignore-file

package workos

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func cacheTestJWK(t *testing.T, kid string) *JWKSResponseKeys {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &JWKSResponseKeys{
		Kid: kid, Kty: "RSA", Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func ageSessionJWKS(client *Client, age time.Duration) {
	sessionJWKSCache.Lock()
	defer sessionJWKSCache.Unlock()
	entry := sessionJWKSCache.entries[client.JWKSURLFromClient()]
	entry.attemptAt = time.Now().Add(-age)
	entry.fetchedAt = time.Now().Add(-age)
	sessionJWKSCache.entries[client.JWKSURLFromClient()] = entry
}

func TestSessionJWKSRotationAndExpiry(t *testing.T) {
	first, rotated := cacheTestJWK(t, "first"), cacheTestJWK(t, "rotated")
	var rotation, unavailable atomic.Bool
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		key := first
		if rotation.Load() {
			key = rotated
		}
		_ = json.NewEncoder(w).Encode(JWKSResponse{Keys: []*JWKSResponseKeys{key}})
	}))
	defer server.Close()
	client := NewClient("sk_test", WithBaseURL(server.URL), WithClientID("rotation"))
	ctx := context.Background()
	_, err := client.sessionVerificationKey(ctx, first.Kid)
	require.NoError(t, err)
	rotation.Store(true)
	_, err = client.sessionVerificationKey(ctx, rotated.Kid)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrSigningKeyUnavailable, "a kid missing from a fresh key set is an invalid token")
	require.Equal(t, int32(1), requests.Load())
	ageSessionJWKS(client, jwksRefreshCooldown+time.Second)
	_, err = client.sessionVerificationKey(ctx, rotated.Kid)
	require.NoError(t, err)
	require.Equal(t, int32(2), requests.Load())
	_, err = client.sessionVerificationKey(ctx, first.Kid)
	require.Error(t, err, "removed key must not remain cached")
	ageSessionJWKS(client, jwksCacheTTL+time.Second)
	unavailable.Store(true)
	_, err = client.sessionVerificationKey(ctx, rotated.Kid)
	require.ErrorIs(t, err, ErrSigningKeyUnavailable, "expired cached keys must not bypass a failed fetch")
	_, err = client.sessionVerificationKey(ctx, rotated.Kid)
	require.ErrorIs(t, err, ErrSigningKeyUnavailable)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr, "the cooldown must report why the last fetch failed")
	require.Equal(t, http.StatusServiceUnavailable, apiErr.StatusCode)
	require.Equal(t, int32(3), requests.Load(), "upstream errors must also respect cooldown")
}

func TestSessionJWKSCacheBoundAndClientIDIsolation(t *testing.T) {
	jwk := cacheTestJWK(t, "key")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(JWKSResponse{Keys: []*JWKSResponseKeys{jwk}})
	}))
	defer server.Close()
	// The least recently attempted entry still has a fetch in flight: evicting
	// it would discard the result and make the callers waiting on it fetch again.
	inflightURL, inflight := "https://inflight.example/sso/jwks/client", make(chan struct{})
	sessionJWKSCache.Lock()
	sessionJWKSCache.entries[inflightURL] = cachedSessionJWKS{attemptAt: time.Now().Add(-time.Hour), loading: inflight}
	sessionJWKSCache.Unlock()
	t.Cleanup(func() {
		sessionJWKSCache.Lock()
		delete(sessionJWKSCache.entries, inflightURL)
		sessionJWKSCache.Unlock()
		close(inflight)
	})
	for i := 0; i < jwksCacheLimit+1; i++ {
		client := NewClient("sk_test", WithBaseURL(server.URL), WithClientID(fmt.Sprintf("client_%d", i)))
		_, err := client.sessionVerificationKey(context.Background(), jwk.Kid)
		require.NoError(t, err)
	}
	require.Equal(t, int32(jwksCacheLimit+1), requests.Load(), "client IDs must have independent cache entries")
	sessionJWKSCache.RLock()
	count := len(sessionJWKSCache.entries)
	_, kept := sessionJWKSCache.entries[inflightURL]
	sessionJWKSCache.RUnlock()
	require.LessOrEqual(t, count, jwksCacheLimit)
	require.True(t, kept, "eviction must not drop an entry with a fetch in flight")
}

func TestSessionJWKSEvictionStaysBoundedWhenAllInflight(t *testing.T) {
	jwk := cacheTestJWK(t, "key")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(JWKSResponse{Keys: []*JWKSResponseKeys{jwk}})
	}))
	defer server.Close()
	// Fill the cache with in-flight entries only; the oldest attempt is entry 0.
	inflight := make(chan struct{})
	sessionJWKSCache.Lock()
	saved := sessionJWKSCache.entries
	sessionJWKSCache.entries = make(map[string]cachedSessionJWKS)
	for i := 0; i < jwksCacheLimit; i++ {
		sessionJWKSCache.entries[fmt.Sprintf("https://inflight.example/%d", i)] = cachedSessionJWKS{
			attemptAt: time.Now().Add(time.Duration(i-jwksCacheLimit) * time.Second), loading: inflight,
		}
	}
	sessionJWKSCache.Unlock()
	t.Cleanup(func() {
		sessionJWKSCache.Lock()
		sessionJWKSCache.entries = saved
		sessionJWKSCache.Unlock()
		close(inflight)
	})
	client := NewClient("sk_test", WithBaseURL(server.URL), WithClientID("bounded"))
	_, err := client.sessionVerificationKey(context.Background(), jwk.Kid)
	require.NoError(t, err)
	sessionJWKSCache.RLock()
	count := len(sessionJWKSCache.entries)
	_, oldestKept := sessionJWKSCache.entries["https://inflight.example/0"]
	_, newestKept := sessionJWKSCache.entries[fmt.Sprintf("https://inflight.example/%d", jwksCacheLimit-1)]
	sessionJWKSCache.RUnlock()
	require.Equal(t, jwksCacheLimit, count, "cache must stay bounded when every entry is in flight")
	require.False(t, oldestKept, "the oldest in-flight entry must be the one evicted")
	require.True(t, newestKept)
}

func TestSessionJWKSInflightWaitRespectsContext(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := NewClient("sk_test", WithBaseURL(server.URL), WithClientID("waiting"))
	done := make(chan struct{})
	defer func() {
		close(release)
		<-done
	}()
	go func() {
		defer close(done)
		_, _ = client.sessionVerificationKey(context.Background(), "key")
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.sessionVerificationKey(ctx, "key")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, ErrSigningKeyUnavailable)
	// A different URL must not wait for the blocked network request either.
	otherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer otherServer.Close()
	other := NewClient("sk_test", WithBaseURL(otherServer.URL), WithClientID("other"))
	otherCtx, otherCancel := context.WithTimeout(context.Background(), time.Second)
	defer otherCancel()
	_, err = other.sessionVerificationKey(otherCtx, "key")
	require.ErrorContains(t, err, "unknown JWT signing key")
}

// A caller that gives up on its own fetch has not learned anything about
// upstream, so the next caller must be allowed to try again at once.
func TestSessionJWKSCanceledFetchDoesNotStartCooldown(t *testing.T) {
	jwk := cacheTestJWK(t, "key")
	t.Run("cancellation", func(t *testing.T) {
		started := make(chan struct{})
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) == 1 {
				close(started)
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(JWKSResponse{Keys: []*JWKSResponseKeys{jwk}})
		}))
		defer server.Close()
		client := NewClient("sk_test", WithBaseURL(server.URL), WithClientID("canceled"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-started
			cancel()
		}()
		_, err := client.sessionVerificationKey(ctx, jwk.Kid)
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, ErrSigningKeyUnavailable)
		_, err = client.sessionVerificationKey(context.Background(), jwk.Kid)
		require.NoError(t, err, "a canceled fetch must not hold the next caller in the cooldown")
		require.Equal(t, int32(2), requests.Load())
	})
	t.Run("deadline", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			<-r.Context().Done()
		}))
		defer server.Close()
		client := NewClient("sk_test", WithBaseURL(server.URL), WithClientID("deadline"))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := client.sessionVerificationKey(ctx, jwk.Kid)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorIs(t, err, ErrSigningKeyUnavailable)
		_, err = client.sessionVerificationKey(context.Background(), jwk.Kid)
		require.ErrorIs(t, err, ErrSigningKeyUnavailable, "a deadline may mean a slow upstream, so the cooldown stays")
		require.ErrorIs(t, err, context.DeadlineExceeded, "the cooldown carries the failed fetch's cause")
		require.ErrorContains(t, err, "retry cooldown after a failed fetch")
		require.Equal(t, int32(1), requests.Load())
	})
}

func TestSessionJWKSRejectsInvalidKeyMetadata(t *testing.T) {
	valid := cacheTestJWK(t, "key")
	// A key set that was fetched but holds no usable key for the kid is an
	// invalid token. An ambiguous key set cannot be trusted at all, so the
	// token is not judged and callers may retry once it is corrected.
	for _, tc := range []struct {
		name        string
		mutate      func(*JWKSResponseKeys)
		unavailable bool
	}{
		{"algorithm", func(k *JWKSResponseKeys) { k.Alg = "HS256" }, false},
		{"key type", func(k *JWKSResponseKeys) { k.Kty = "EC" }, false},
		{"key use", func(k *JWKSResponseKeys) { k.Use = "enc" }, false},
		{"exponent", func(k *JWKSResponseKeys) { k.E = "AA" }, false},
		{"weak modulus", func(k *JWKSResponseKeys) { k.N = "AQAB" }, false},
		{"duplicate key ID", func(k *JWKSResponseKeys) {}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := *valid
			tc.mutate(&jwk)
			keys := []*JWKSResponseKeys{&jwk}
			if tc.name == "duplicate key ID" {
				keys = append(keys, valid)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(JWKSResponse{Keys: keys})
			}))
			defer server.Close()
			client := NewClient("sk_test", WithBaseURL(server.URL), WithClientID("invalid"))
			_, err := client.sessionVerificationKey(context.Background(), valid.Kid)
			if tc.unavailable {
				require.ErrorIs(t, err, ErrSigningKeyUnavailable)
			} else {
				require.ErrorContains(t, err, "unknown JWT signing key")
				require.NotErrorIs(t, err, ErrSigningKeyUnavailable)
			}
		})
	}
}
