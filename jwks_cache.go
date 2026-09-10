// @oagen-ignore-file

package workos

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	sessionVerificationTimeout = 5 * time.Second
	sessionJWTLeeway           = 60 * time.Second
	jwksCacheTTL               = 5 * time.Minute
	jwksRefreshCooldown        = 30 * time.Second
	jwksCacheLimit             = 128
)

type cachedSessionJWKS struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	attemptAt time.Time
	loading   chan struct{}
}

// Key sets are shared by sessions using the same configured JWKS URL. Bound
// both their lifetime and their count; an unknown kid cannot trigger a fetch
// more than once per cooldown, including when the upstream is unavailable.
var sessionJWKSCache = struct {
	sync.RWMutex
	entries map[string]cachedSessionJWKS
}{entries: make(map[string]cachedSessionJWKS)}

func (c *Client) sessionVerificationKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	cacheURL := c.JWKSURLFromClient()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sessionJWKSCache.RLock()
		entry := sessionJWKSCache.entries[cacheURL]
		key := entry.keys[kid]
		fresh := time.Since(entry.fetchedAt) < jwksCacheTTL
		sessionJWKSCache.RUnlock()
		if fresh && key != nil {
			return key, nil
		}
		if entry.loading != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-entry.loading:
				continue
			}
		}

		sessionJWKSCache.Lock()
		entry = sessionJWKSCache.entries[cacheURL]
		if entry.loading != nil || (time.Since(entry.fetchedAt) < jwksCacheTTL && entry.keys[kid] != nil) {
			sessionJWKSCache.Unlock()
			continue
		}
		if time.Since(entry.attemptAt) < jwksRefreshCooldown {
			sessionJWKSCache.Unlock()
			return nil, errors.New("workos: JWT signing key unavailable")
		}
		if _, exists := sessionJWKSCache.entries[cacheURL]; !exists && len(sessionJWKSCache.entries) >= jwksCacheLimit {
			var oldestURL string
			var oldest time.Time
			for url, cached := range sessionJWKSCache.entries {
				if oldestURL == "" || cached.attemptAt.Before(oldest) {
					oldestURL, oldest = url, cached.attemptAt
				}
			}
			delete(sessionJWKSCache.entries, oldestURL)
		}
		loading := make(chan struct{})
		entry.attemptAt, entry.loading = time.Now(), loading
		sessionJWKSCache.entries[cacheURL] = entry
		sessionJWKSCache.Unlock()

		// Never hold the global lock during I/O: an unavailable JWKS endpoint
		// must not block other clients or callers with shorter deadlines.
		keys, err := c.fetchSessionJWKS(ctx)
		sessionJWKSCache.Lock()
		if sessionJWKSCache.entries[cacheURL].loading == loading {
			entry.loading = nil
			if err == nil {
				entry.keys, entry.fetchedAt = keys, time.Now()
			}
			sessionJWKSCache.entries[cacheURL] = entry
		}
		close(loading)
		sessionJWKSCache.Unlock()
		if err != nil {
			return nil, err
		}
		if keys[kid] == nil {
			return nil, errors.New("workos: unknown JWT signing key")
		}
		return keys[kid], nil
	}
}

func (c *Client) fetchSessionJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	jwks, err := c.UserManagement().GetJWKS(ctx, c.clientID, WithRequestMaxRetries(0))
	if err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk == nil || jwk.Kid == "" || jwk.Kty != "RSA" || (jwk.Alg != "" && jwk.Alg != "RS256") || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil || len(n) == 0 {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		exponent := new(big.Int).SetBytes(e).Int64()
		modulus := new(big.Int).SetBytes(n)
		if exponent < 3 || exponent > 1<<31-1 || exponent%2 == 0 || modulus.BitLen() < 2048 {
			continue
		}
		if _, duplicate := keys[jwk.Kid]; duplicate {
			return nil, errors.New("workos: duplicate JWT signing key ID")
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	return keys, nil
}

// verifyAccessToken verifies the signature and identity claims before returning
// any authorization claims. Expiration is handled by Authenticate so verified,
// expired tokens can still be used to refresh and log out.
func (s *Session) verifyAccessToken(ctx context.Context, token string) (*JWTClaims, error) {
	if s.client == nil || s.client.clientID == "" {
		return nil, errors.New("workos: a client configured with WithClientID is required for session authentication")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("workos: invalid JWT format")
	}
	var header struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, err
	}
	if header.Alg != "RS256" || header.Kid == "" || len(header.Crit) != 0 {
		return nil, errors.New("workos: unsupported JWT header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, sessionVerificationTimeout)
	defer cancel()
	key, err := s.client.sessionVerificationKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, err
	}
	decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload struct {
		JWTClaims
		Issuer    string          `json:"iss"`
		Audience  json.RawMessage `json:"aud"`
		NotBefore int64           `json:"nbf"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, err
	}
	if strings.TrimRight(s.issuer, "/") == "" || strings.TrimRight(payload.Issuer, "/") != strings.TrimRight(s.issuer, "/") {
		return nil, errors.New("workos: invalid JWT issuer")
	}
	if payload.NotBefore > time.Now().Add(sessionJWTLeeway).Unix() {
		return nil, errors.New("workos: JWT is not yet valid")
	}
	if len(payload.Audience) != 0 {
		var audience string
		var audiences []string
		if err := json.Unmarshal(payload.Audience, &audience); err == nil && audience != "" {
			audiences = []string{audience}
		} else if err := json.Unmarshal(payload.Audience, &audiences); err != nil {
			return nil, errors.New("workos: invalid JWT audience")
		}
		matched := false
		for _, aud := range audiences {
			matched = matched || aud == s.client.clientID
		}
		if !matched {
			return nil, errors.New("workos: invalid JWT audience")
		}
	}
	return &payload.JWTClaims, nil
}
