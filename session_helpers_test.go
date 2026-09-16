// @oagen-ignore-file

package workos_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v10"
)

const testCookiePassword = "test-cookie-password-for-session-helpers"

// buildFakeJWT builds a fake JWT: header.payload.signature
func buildFakeJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sid":"sess_123","org_id":"org_456","role":"admin","permissions":["read","write"]}`))
	return header + "." + payload + ".fakesig"
}

func TestSealSessionFromAuthResponse_SealAndUnseal(t *testing.T) {
	fakeJWT := buildFakeJWT()

	user := &workos.User{
		ID:    "user_123",
		Email: "test@example.com",
	}

	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		user,
		nil, // no impersonator
		testCookiePassword,
	)
	require.NoError(t, err)
	require.NotEmpty(t, sealed)

	// Verify the sealed data can be unsealed
	unsealed, err := workos.UnsealData(sealed, testCookiePassword)
	require.NoError(t, err)
	require.Equal(t, fakeJWT, unsealed["access_token"])
	require.Equal(t, "refresh_tok_abc", unsealed["refresh_token"])

	userMap, ok := unsealed["user"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "user_123", userMap["id"])
	require.Equal(t, "test@example.com", userMap["email"])
}

func TestSealSessionFromAuthResponse_WithImpersonator(t *testing.T) {
	fakeJWT := buildFakeJWT()

	user := &workos.User{ID: "user_123"}
	impersonator := &workos.AuthenticateResponseImpersonator{
		Email:  "admin@example.com",
		Reason: ptrString("debugging"),
	}

	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		user,
		impersonator,
		testCookiePassword,
	)
	require.NoError(t, err)
	require.NotEmpty(t, sealed)

	unsealed, err := workos.UnsealData(sealed, testCookiePassword)
	require.NoError(t, err)

	impMap, ok := unsealed["impersonator"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "admin@example.com", impMap["email"])
}

func TestAuthenticateSession_ValidSession(t *testing.T) {
	client, token := signedSessionFixture(t, sessionTestClaims())

	// Seal a session containing a WorkOS-signed access token.
	sealed, err := workos.SealSessionFromAuthResponse(
		token,
		"refresh_tok_abc",
		&workos.User{ID: "user_123", Email: "test@example.com"},
		nil,
		testCookiePassword,
	)
	require.NoError(t, err)

	result, err := client.AuthenticateSession(context.Background(), sealed, testCookiePassword)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Authenticated)
	require.Equal(t, "sess_123", result.SessionID)
	require.Equal(t, "org_456", result.OrganizationID)
	require.Equal(t, "admin", result.Role)
	require.Equal(t, []string{"read", "write"}, result.Permissions)

	// User data should be populated
	require.NotNil(t, result.User)
	require.Equal(t, "user_123", result.User.ID)
}

func TestAuthenticateSession_EmptySession(t *testing.T) {
	result, err := workos.AuthenticateSession("", testCookiePassword)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.Authenticated)
	require.Equal(t, "no_session_cookie_provided", result.Reason)
}

func TestAuthenticateSession_InvalidSealedData(t *testing.T) {
	result, err := workos.AuthenticateSession("not-valid-sealed-data", testCookiePassword)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.Authenticated)
	require.Equal(t, "invalid_session_cookie", result.Reason)
}

func TestAuthenticateSession_WrongPassword(t *testing.T) {
	fakeJWT := buildFakeJWT()

	sealed, err := workos.SealSessionFromAuthResponse(
		fakeJWT,
		"refresh_tok_abc",
		nil,
		nil,
		testCookiePassword,
	)
	require.NoError(t, err)

	// Try to unseal with the wrong password
	result, err := workos.AuthenticateSession(sealed, "wrong-password")
	require.NoError(t, err)
	require.False(t, result.Authenticated)
	require.Equal(t, "invalid_session_cookie", result.Reason)
}

func TestNewSession_Authenticate(t *testing.T) {
	client, token := signedSessionFixture(t, sessionTestClaims())

	sealed, err := workos.SealSessionFromAuthResponse(
		token,
		"refresh_tok_abc",
		&workos.User{ID: "user_789"},
		nil,
		testCookiePassword,
	)
	require.NoError(t, err)

	// Create a Session object and authenticate
	session := workos.NewSession(client, sealed, testCookiePassword)
	require.NotNil(t, session)

	result, err := session.Authenticate()
	require.NoError(t, err)
	require.True(t, result.Authenticated)
	require.Equal(t, "sess_123", result.SessionID)
	require.Equal(t, "org_456", result.OrganizationID)
	require.Equal(t, "admin", result.Role)
	require.Equal(t, []string{"read", "write"}, result.Permissions)
	require.NotNil(t, result.User)
	require.Equal(t, "user_789", result.User.ID)
}

func TestNewSession_Authenticate_EmptySession(t *testing.T) {
	session := workos.NewSession(nil, "", testCookiePassword)
	result, err := session.Authenticate()
	require.NoError(t, err)
	require.False(t, result.Authenticated)
	require.Equal(t, "no_session_cookie_provided", result.Reason)
}

// A terminal refresh failure (OAuth invalid_grant) must be labeled
// refresh_token_revoked. The WorkOS token endpoint returns invalid_grant at
// HTTP 400, so detection must not be coupled to a 401 status.
func TestSession_Refresh_InvalidGrantIsTerminal(t *testing.T) {
	fakeJWT := buildFakeJWT()
	sealed, err := workos.SealSessionFromAuthResponse(fakeJWT, "refresh_tok_abc", nil, nil, testCookiePassword)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/user_management/authenticate", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token is invalid."}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.RefreshSession(context.Background(), sealed, testCookiePassword)
	require.Error(t, err)
	require.NotNil(t, result)
	require.False(t, result.Authenticated)
	require.Equal(t, "refresh_token_revoked", result.Reason)
}

// A non-invalid_grant failure (e.g. a generic 400) is not a dead token, so it
// must remain the generic refresh_failed rather than being reported as revoked.
func TestSession_Refresh_NonInvalidGrantIsNotRevoked(t *testing.T) {
	fakeJWT := buildFakeJWT()
	sealed, err := workos.SealSessionFromAuthResponse(fakeJWT, "refresh_tok_abc", nil, nil, testCookiePassword)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"Something else."}`))
	}))
	defer server.Close()

	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL))
	result, err := client.RefreshSession(context.Background(), sealed, testCookiePassword)
	require.Error(t, err)
	require.NotNil(t, result)
	require.False(t, result.Authenticated)
	require.Equal(t, "refresh_failed", result.Reason)
}

// Refresh must never spend the caller's context on a JWKS request: the
// organization hint is optional, so it is sent only when the signing key is
// already cached, and an unavailable JWKS endpoint cannot block a valid refresh.
func TestSession_Refresh_UsesOnlyCachedJWKS(t *testing.T) {
	key := sessionTestKey(t)
	sealed := sealSessionToken(t, signSessionJWT(t, key, map[string]any{"alg": "RS256", "kid": "session-key"}, sessionTestClaims()))
	var jwksAvailable atomic.Bool
	hints := make(chan *string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/sso/jwks/client_session":
			if !jwksAvailable.Load() {
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(workos.JWKSResponse{Keys: []*workos.JWKSResponseKeys{sessionTestJWK(key)}})
		case "/user_management/authenticate":
			var body struct {
				OrganizationID *string `json:"organization_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			hints <- body.OrganizationID
			_, _ = w.Write([]byte(`{"access_token":"new_access","refresh_token":"new_refresh"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL), workos.WithClientID("client_session"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Cold cache while the JWKS endpoint hangs: refresh immediately, without a hint.
	result, err := client.RefreshSession(ctx, sealed, testCookiePassword)
	require.NoError(t, err)
	require.True(t, result.Authenticated)
	require.Nil(t, <-hints)

	// Warm cache: the verified organization_id is sent as the hint.
	jwksAvailable.Store(true)
	auth, err := client.AuthenticateSession(ctx, sealed, testCookiePassword)
	require.NoError(t, err)
	require.True(t, auth.Authenticated)
	result, err = client.RefreshSession(ctx, sealed, testCookiePassword)
	require.NoError(t, err)
	require.True(t, result.Authenticated)
	hint := <-hints
	require.NotNil(t, hint)
	require.Equal(t, "org_456", *hint)
}

// GetLogoutURL must succeed for a session whose access token has expired:
// the JWT exp check makes Authenticate return Authenticated=false with
// SessionID populated, and the logout endpoint accepts that session ID
// regardless of access-token freshness.
func TestSession_GetLogoutURL_ExpiredJWT(t *testing.T) {
	claims := sessionTestClaims()
	claims["sid"] = "sess_expired"
	claims["exp"] = 1
	client, expiredJWT := signedSessionFixture(t, claims)

	sealed, err := workos.SealSessionFromAuthResponse(
		expiredJWT,
		"refresh_tok_abc",
		&workos.User{ID: "user_123"},
		nil,
		testCookiePassword,
	)
	require.NoError(t, err)

	session := workos.NewSession(client, sealed, testCookiePassword)
	logoutURL, err := session.GetLogoutURL(context.Background(), "")
	require.NoError(t, err)
	require.Contains(t, logoutURL, "session_id=sess_expired")
}

func TestAuthenticateSession_NoAccessToken(t *testing.T) {
	// Seal data that has no access_token field
	data := map[string]interface{}{
		"refresh_token": "refresh_tok_abc",
	}
	sealed, err := workos.SealData(data, testCookiePassword)
	require.NoError(t, err)

	result, err := workos.AuthenticateSession(sealed, testCookiePassword)
	require.ErrorContains(t, err, "Client.AuthenticateSession")
	require.False(t, result.Authenticated)
	require.Equal(t, "invalid_jwt", result.Reason)
}

func sessionTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func sessionTestJWK(key *rsa.PrivateKey) *workos.JWKSResponseKeys {
	return &workos.JWKSResponseKeys{
		Kid: "session-key", Kty: "RSA", Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func sessionTestClient(t *testing.T, jwks *workos.JWKSResponse) (*workos.Client, *atomic.Int32) {
	t.Helper()
	requests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/sso/jwks/client_session" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(server.Close)
	return workos.NewClient("sk_test", workos.WithBaseURL(server.URL), workos.WithClientID("client_session")), requests
}

func sessionTestClaims() map[string]any {
	return map[string]any{
		"iss": "https://api.workos.com/", "sub": "user_123", "sid": "sess_123",
		"org_id": "org_456", "role": "admin", "permissions": []string{"read", "write"},
		"entitlements": []string{"feature_a"}, "exp": time.Now().Add(time.Hour).Unix(),
	}
}

func signSessionJWT(t *testing.T, key *rsa.PrivateKey, header, claims any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signedSessionFixture(t *testing.T, claims map[string]any) (*workos.Client, string) {
	t.Helper()
	key := sessionTestKey(t)
	client, _ := sessionTestClient(t, &workos.JWKSResponse{Keys: []*workos.JWKSResponseKeys{sessionTestJWK(key)}})
	return client, signSessionJWT(t, key, map[string]any{"alg": "RS256", "kid": "session-key"}, claims)
}

func sealSessionToken(t *testing.T, token string) string {
	t.Helper()
	sealed, err := workos.SealSessionFromAuthResponse(token, "refresh_token", &workos.User{ID: "user_123"}, nil, testCookiePassword)
	require.NoError(t, err)
	return sealed
}

func TestSessionJWTVerification(t *testing.T) {
	key := sessionTestKey(t)
	attackerKey := sessionTestKey(t)
	client, _ := sessionTestClient(t, &workos.JWKSResponse{Keys: []*workos.JWKSResponseKeys{sessionTestJWK(key)}})
	tests := []struct {
		name          string
		change        func(map[string]any, map[string]any)
		mutate        func(string) string
		key           *rsa.PrivateKey
		authenticated bool
		expired       bool
	}{
		{name: "valid without audience", authenticated: true},
		{name: "token URLs do not select keys", change: func(h, c map[string]any) {
			h["jku"] = "http://127.0.0.1:1/attacker-jwks"
			h["x5u"] = "http://127.0.0.1:1/attacker-cert"
		}, authenticated: true},
		{name: "issuer without trailing slash", change: func(h, c map[string]any) { c["iss"] = "https://api.workos.com" }, authenticated: true},
		{name: "string audience", change: func(h, c map[string]any) { c["aud"] = "client_session" }, authenticated: true},
		{name: "array audience", change: func(h, c map[string]any) { c["aud"] = []string{"other", "client_session"} }, authenticated: true},
		{name: "wrong audience", change: func(h, c map[string]any) { c["aud"] = "other" }},
		{name: "wrong audience array", change: func(h, c map[string]any) { c["aud"] = []string{"other"} }},
		{name: "malformed audience", change: func(h, c map[string]any) { c["aud"] = 123 }},
		{name: "null audience", change: func(h, c map[string]any) { c["aud"] = nil }},
		{name: "wrong issuer", change: func(h, c map[string]any) { c["iss"] = "https://attacker.example/" }},
		{name: "missing issuer", change: func(h, c map[string]any) { delete(c, "iss") }},
		{name: "none algorithm", change: func(h, c map[string]any) { h["alg"] = "none" }},
		{name: "HS256 algorithm confusion", change: func(h, c map[string]any) { h["alg"] = "HS256" }},
		{name: "RS512 algorithm", change: func(h, c map[string]any) { h["alg"] = "RS512" }},
		{name: "missing kid", change: func(h, c map[string]any) { delete(h, "kid") }},
		{name: "unknown kid", change: func(h, c map[string]any) { h["kid"] = "attacker" }},
		{name: "unsupported critical header", change: func(h, c map[string]any) { h["crit"] = []string{"custom"} }},
		{name: "wrong signing key", key: attackerKey},
		{name: "not yet valid", change: func(h, c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{name: "nbf within leeway", change: func(h, c map[string]any) { c["nbf"] = time.Now().Add(30 * time.Second).Unix() }, authenticated: true},
		{name: "expired", change: func(h, c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, expired: true},
		{name: "recently expired", change: func(h, c map[string]any) { c["exp"] = time.Now().Add(-30 * time.Second).Unix() }, expired: true},
		{name: "expires now", change: func(h, c map[string]any) { c["exp"] = time.Now().Unix() }, expired: true},
		{name: "no expiration preserves existing behavior", change: func(h, c map[string]any) { delete(c, "exp") }, authenticated: true},
		{name: "expired forged token", key: attackerKey, change: func(h, c map[string]any) { c["exp"] = 1 }},
		{name: "expired wrong issuer", change: func(h, c map[string]any) { c["exp"] = 1; c["iss"] = "https://attacker.example" }},
		{name: "malformed exp", change: func(h, c map[string]any) { c["exp"] = "tomorrow" }},
		{name: "tampered authorization claims", mutate: func(token string) string {
			parts := strings.Split(token, ".")
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(string(payload), "admin", "superadmin")))
			return strings.Join(parts, ".")
		}},
		{name: "empty signature", mutate: func(token string) string { return token[:strings.LastIndex(token, ".")+1] }},
		{name: "invalid base64 signature", mutate: func(token string) string { return token[:strings.LastIndex(token, ".")+1] + "!" }},
		{name: "malformed token", mutate: func(string) string { return "not.a.jwt.token" }},
		{name: "original fake token regression", mutate: func(string) string { return buildFakeJWT() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := map[string]any{"alg": "RS256", "kid": "session-key"}
			claims := sessionTestClaims()
			if tt.change != nil {
				tt.change(header, claims)
			}
			signingKey := key
			if tt.key != nil {
				signingKey = tt.key
			}
			token := signSessionJWT(t, signingKey, header, claims)
			if tt.mutate != nil {
				token = tt.mutate(token)
			}
			result, err := client.AuthenticateSession(context.Background(), sealSessionToken(t, token), testCookiePassword)
			require.NoError(t, err)
			require.Equal(t, tt.authenticated, result.Authenticated)
			require.Equal(t, tt.expired, result.NeedsRefresh)
			if tt.authenticated || tt.expired {
				require.Equal(t, "sess_123", result.SessionID)
				require.Equal(t, "admin", result.Role)
				require.Equal(t, []string{"feature_a"}, result.Entitlements)
				if tt.expired {
					require.Equal(t, "session_expired", result.Reason)
				}
			} else {
				require.Equal(t, &workos.AuthenticateSessionResult{Reason: "invalid_jwt"}, result)
			}
		})
	}
}

func TestSessionJWTRequiresConfiguredClient(t *testing.T) {
	client, token := signedSessionFixture(t, sessionTestClaims())
	sealed := sealSessionToken(t, token)
	for _, c := range []*workos.Client{nil, workos.NewClient("sk_test")} {
		result, err := workos.NewSession(c, sealed, testCookiePassword).Authenticate()
		require.NoError(t, err)
		require.Equal(t, &workos.AuthenticateSessionResult{Reason: "invalid_jwt"}, result)
	}
	result, err := workos.AuthenticateSession(sealed, testCookiePassword)
	require.ErrorContains(t, err, "Client.AuthenticateSession")
	require.Equal(t, &workos.AuthenticateSessionResult{Reason: "invalid_jwt"}, result)
	result, err = client.AuthenticateSession(context.Background(), sealed, testCookiePassword)
	require.NoError(t, err)
	require.True(t, result.Authenticated)
}

func TestSessionJWTCustomIssuer(t *testing.T) {
	claims := sessionTestClaims()
	claims["iss"] = "https://auth.example.com/"
	client, token := signedSessionFixture(t, claims)
	sealed := sealSessionToken(t, token)
	result, err := client.AuthenticateSession(context.Background(), sealed, testCookiePassword)
	require.NoError(t, err)
	require.Equal(t, "invalid_jwt", result.Reason)
	result, err = client.AuthenticateSession(context.Background(), sealed, testCookiePassword, workos.WithSessionIssuer("https://auth.example.com"))
	require.NoError(t, err)
	require.True(t, result.Authenticated)
}

func TestSessionJWKSCachesAcrossSessionsConcurrently(t *testing.T) {
	key := sessionTestKey(t)
	client, requests := sessionTestClient(t, &workos.JWKSResponse{Keys: []*workos.JWKSResponseKeys{sessionTestJWK(key)}})
	token := signSessionJWT(t, key, map[string]any{"alg": "RS256", "kid": "session-key"}, sessionTestClaims())
	sealed := sealSessionToken(t, token)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := client.AuthenticateSession(context.Background(), sealed, testCookiePassword)
			if err != nil || !result.Authenticated {
				t.Errorf("authentication failed: %v, %+v", err, result)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), requests.Load())
	unknown := signSessionJWT(t, key, map[string]any{"alg": "RS256", "kid": "unknown"}, sessionTestClaims())
	result, err := client.AuthenticateSession(context.Background(), sealSessionToken(t, unknown), testCookiePassword)
	require.NoError(t, err)
	require.Equal(t, "invalid_jwt", result.Reason)
	require.Equal(t, int32(1), requests.Load(), "unknown kids must respect refresh cooldown")
}

func TestSessionJWKSFailures(t *testing.T) {
	key := sessionTestKey(t)
	token := signSessionJWT(t, key, map[string]any{"alg": "RS256", "kid": "session-key"}, sessionTestClaims())
	sealed := sealSessionToken(t, token)
	for _, body := range []string{`not json`, `{}`, `{"keys":[null]}`, `{"keys":[{"kid":"session-key","kty":"RSA","n":"!","e":"AQAB"}]}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL), workos.WithClientID("client_session"))
			result, err := client.AuthenticateSession(context.Background(), sealed, testCookiePassword)
			require.NoError(t, err)
			require.Equal(t, &workos.AuthenticateSessionResult{Reason: "invalid_jwt"}, result)
		})
	}
	t.Run("upstream error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
		defer server.Close()
		client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL), workos.WithClientID("client_session"))
		result, err := client.AuthenticateSession(context.Background(), sealed, testCookiePassword)
		require.NoError(t, err)
		require.Equal(t, &workos.AuthenticateSessionResult{Reason: "invalid_jwt"}, result)
	})
	t.Run("context timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		client := workos.NewClient("sk_test", workos.WithBaseURL(server.URL), workos.WithClientID("client_session"))
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		result, err := client.AuthenticateSession(ctx, sealed, testCookiePassword)
		require.NoError(t, err)
		require.Equal(t, &workos.AuthenticateSessionResult{Reason: "invalid_jwt"}, result)
	})
}

func TestSessionJWKSClientIsolation(t *testing.T) {
	client, token := signedSessionFixture(t, sessionTestClaims())
	sealed := sealSessionToken(t, token)
	result, err := client.AuthenticateSession(context.Background(), sealed, testCookiePassword)
	require.NoError(t, err)
	require.True(t, result.Authenticated)
	other, _ := sessionTestClient(t, &workos.JWKSResponse{Keys: []*workos.JWKSResponseKeys{sessionTestJWK(sessionTestKey(t))}})
	result, err = other.AuthenticateSession(context.Background(), sealed, testCookiePassword)
	require.NoError(t, err)
	require.Equal(t, "invalid_jwt", result.Reason)
}
