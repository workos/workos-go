package usermanagement

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// SessionHelper provides helper methods for working with WorkOS sessions
// This struct is not meant to be instantiated in user space, and is instantiated internally but exposed.
type SessionHelper struct {
	userManagement *Client
	clientID       string
	sessionData    string
	cookiePassword string
	jwks           *keyfunc.JWKS
	jwksAlgorithms []string
	mu             sync.RWMutex
}

// SessionData represents the structure of unsealed session data
type SessionData struct {
	AccessToken  string      `json:"access_token,omitempty"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	User         interface{} `json:"user,omitempty"`
	Impersonator interface{} `json:"impersonator,omitempty"`
}

// AuthenticateResult represents the result of session authentication
type AuthenticateResult struct {
	Authenticated  bool        `json:"authenticated"`
	SessionID      string      `json:"session_id,omitempty"`
	OrganizationID string      `json:"organization_id,omitempty"`
	Role           string      `json:"role,omitempty"`
	Permissions    []string    `json:"permissions,omitempty"`
	Entitlements   []string    `json:"entitlements,omitempty"`
	FeatureFlags   []string    `json:"feature_flags,omitempty"`
	User           interface{} `json:"user,omitempty"`
	Impersonator   interface{} `json:"impersonator,omitempty"`
	Reason         string      `json:"reason,omitempty"`
}

// RefreshResult represents the result of session refresh
type RefreshResult struct {
	Authenticated bool                           `json:"authenticated"`
	SealedSession string                         `json:"sealed_session,omitempty"`
	Session       *RefreshAuthenticationResponse `json:"session,omitempty"`
	Reason        string                         `json:"reason,omitempty"`
}

// RefreshOptions provides options for refreshing a session
type RefreshOptions struct {
	CookiePassword string `json:"cookie_password,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
}

const (
	// JWKS cache duration (5 minutes)
	jwksCacheDuration = 5 * time.Minute
)

// NewSessionHelper creates a new session helper instance
func NewSessionHelper(userManagement *Client, clientID, sessionData, cookiePassword string) (*SessionHelper, error) {
	if cookiePassword == "" {
		return nil, errors.New("cookiePassword is required")
	}

	sh := &SessionHelper{
		userManagement: userManagement,
		clientID:       clientID,
		sessionData:    sessionData,
		cookiePassword: cookiePassword,
	}

	// Initialize JWKS
	if err := sh.initJWKS(); err != nil {
		return nil, fmt.Errorf("failed to initialize JWKS: %w", err)
	}

	return sh, nil
}

// initJWKS initializes the JWKS for JWT validation
func (sh *SessionHelper) initJWKS() error {
	jwksURL, err := sh.userManagement.GetJWKSURL(sh.clientID)
	if err != nil {
		return fmt.Errorf("failed to get JWKS URL: %w", err)
	}

	// Create JWKS instance with auto-refresh
	jwks, err := keyfunc.Get(jwksURL.String(), keyfunc.Options{
		RefreshInterval:  jwksCacheDuration,
		RefreshRateLimit: time.Minute * 5,
		RefreshTimeout:   time.Second * 10,
		RefreshErrorHandler: func(err error) {
			// Log error but don't fail
			fmt.Printf("JWKS refresh error: %v\n", err)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create JWKS: %w", err)
	}

	sh.mu.Lock()
	sh.jwks = jwks
	sh.mu.Unlock()

	return nil
}

// Authenticate authenticates the user based on the session data
func (sh *SessionHelper) Authenticate() AuthenticateResult {
	if sh.sessionData == "" {
		return AuthenticateResult{
			Authenticated: false,
			Reason:        "NO_SESSION_COOKIE_PROVIDED",
		}
	}

	// Unseal session data
	sessionData, err := UnsealData(sh.sessionData, sh.cookiePassword)
	if err != nil {
		return AuthenticateResult{
			Authenticated: false,
			Reason:        "INVALID_SESSION_COOKIE",
		}
	}

	if sessionData.AccessToken == "" {
		return AuthenticateResult{
			Authenticated: false,
			Reason:        "INVALID_SESSION_COOKIE",
		}
	}

	// Validate JWT
	if !sh.isValidJWT(sessionData.AccessToken) {
		return AuthenticateResult{
			Authenticated: false,
			Reason:        "INVALID_JWT",
		}
	}

	// Parse JWT claims
	sh.mu.RLock()
	jwks := sh.jwks
	sh.mu.RUnlock()

	token, err := jwt.Parse(sessionData.AccessToken, jwks.Keyfunc)
	if err != nil {
		return AuthenticateResult{
			Authenticated: false,
			Reason:        "INVALID_JWT",
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return AuthenticateResult{
			Authenticated: false,
			Reason:        "INVALID_JWT",
		}
	}

	// Convert jwt.MapClaims to map[string]interface{}
	claimsMap := make(map[string]interface{})
	for k, v := range claims {
		claimsMap[k] = v
	}

	// Extract claims with safe type conversion
	result := AuthenticateResult{
		Authenticated:  true,
		SessionID:      getStringClaim(claimsMap, "sid"),
		OrganizationID: getStringClaim(claimsMap, "org_id"),
		Role:           getStringClaim(claimsMap, "role"),
		Permissions:    getStringSliceClaim(claimsMap, "permissions"),
		Entitlements:   getStringSliceClaim(claimsMap, "entitlements"),
		FeatureFlags:   getStringSliceClaim(claimsMap, "feature_flags"),
		User:           sessionData.User,
		Impersonator:   sessionData.Impersonator,
	}

	return result
}

// Refresh refreshes the session data using the refresh token stored in the session data
func (sh *SessionHelper) Refresh(options *RefreshOptions) RefreshResult {
	cookiePassword := sh.cookiePassword
	if options != nil && options.CookiePassword != "" {
		cookiePassword = options.CookiePassword
	}

	// Unseal session data
	sessionData, err := UnsealData(sh.sessionData, cookiePassword)
	if err != nil {
		return RefreshResult{
			Authenticated: false,
			Reason:        "INVALID_SESSION_COOKIE",
		}
	}

	if sessionData.RefreshToken == "" || sessionData.User == nil {
		return RefreshResult{
			Authenticated: false,
			Reason:        "INVALID_SESSION_COOKIE",
		}
	}

	// Prepare refresh options
	refreshOpts := AuthenticateWithRefreshTokenOpts{
		ClientID:     sh.clientID,
		RefreshToken: sessionData.RefreshToken,
	}

	if options != nil && options.OrganizationID != "" {
		refreshOpts.OrganizationID = options.OrganizationID
	}

	// Authenticate with refresh token
	authResponse, err := sh.userManagement.AuthenticateWithRefreshToken(context.Background(), refreshOpts)
	if err != nil {
		return RefreshResult{
			Authenticated: false,
			Reason:        err.Error(),
		}
	}

	// Create new session data with updated tokens
	newSessionData := SessionData{
		AccessToken:  authResponse.AccessToken,
		RefreshToken: authResponse.RefreshToken,
		User:         sessionData.User,
		Impersonator: sessionData.Impersonator,
	}

	// Seal the new session data
	newSealedSession, err := SealData(newSessionData, cookiePassword)
	if err != nil {
		return RefreshResult{
			Authenticated: false,
			Reason:        fmt.Sprintf("failed to seal new session: %v", err),
		}
	}

	// Update session data
	sh.mu.Lock()
	sh.sessionData = newSealedSession
	sh.cookiePassword = cookiePassword
	sh.mu.Unlock()

	return RefreshResult{
		Authenticated: true,
		SealedSession: newSealedSession,
		Session:       &authResponse,
		Reason:        "",
	}
}

// GetLogoutURL returns a URL to redirect the user to for logging out
func (sh *SessionHelper) GetLogoutURL(returnTo string) (string, error) {
	authResult := sh.Authenticate()
	if !authResult.Authenticated {
		return "", fmt.Errorf("failed to extract session ID for logout URL: %s", authResult.Reason)
	}

	opts := GetLogoutURLOpts{
		SessionID: authResult.SessionID,
	}
	if returnTo != "" {
		opts.ReturnTo = returnTo
	}

	logoutURL, err := sh.userManagement.GetLogoutURL(opts)
	if err != nil {
		return "", fmt.Errorf("failed to get logout URL: %w", err)
	}

	return logoutURL.String(), nil
}

// isValidJWT validates a JWT token using the JWKS set
func (sh *SessionHelper) isValidJWT(tokenString string) bool {
	sh.mu.RLock()
	jwks := sh.jwks
	sh.mu.RUnlock()

	if jwks == nil {
		return false
	}

	_, err := jwt.Parse(tokenString, jwks.Keyfunc)
	return err == nil
}

// SealData encrypts and seals data using AES-256-GCM
func SealData(data interface{}, key string) (string, error) {
	// Convert data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	// Create cipher
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("key must be exactly 32 bytes for AES-256, got %d bytes", len(keyBytes))
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, jsonData, nil)

	// Encode as base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// UnsealData decrypts and unseals data using AES-256-GCM
func UnsealData(sealedData, key string) (*SessionData, error) {
	// Decode from base64
	combined, err := base64.StdEncoding.DecodeString(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create cipher
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes for AES-256, got %d bytes", len(keyBytes))
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length
	nonceSize := gcm.NonceSize()
	if len(combined) < nonceSize {
		return nil, errors.New("sealed data too short")
	}

	// Extract nonce and ciphertext
	nonce := combined[:nonceSize]
	ciphertext := combined[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Parse JSON
	var sessionData SessionData
	if err := json.Unmarshal(plaintext, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return &sessionData, nil
}

// Helper functions for safe type conversion from JWT claims

func getStringClaim(claims map[string]interface{}, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getStringSliceClaim(claims map[string]interface{}, key string) []string {
	if val, ok := claims[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}
