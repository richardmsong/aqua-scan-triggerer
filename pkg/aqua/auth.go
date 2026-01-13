package aqua

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// AuthMode represents the authentication mode for Aqua API
type AuthMode string

const (
	// AuthModeToken uses a static API token (Bearer token)
	AuthModeToken AuthMode = "token"

	// AuthModeCredentials uses username/password to acquire tokens
	AuthModeCredentials AuthMode = "credentials"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// Mode specifies the authentication mode
	Mode AuthMode

	// Token is used when Mode is AuthModeToken
	Token string

	// Username is used when Mode is AuthModeCredentials
	Username string

	// Password is used when Mode is AuthModeCredentials
	Password string

	// HMACSecret is used for HMAC256 request signing (optional)
	HMACSecret string

	// TokenRefreshBuffer is the duration before token expiry to refresh
	// Default: 5 minutes
	TokenRefreshBuffer time.Duration
}

// TokenInfo contains information about an acquired token
type TokenInfo struct {
	// AccessToken is the token to use for API requests
	AccessToken string `json:"token"`

	// ExpiresAt is when the token expires
	ExpiresAt time.Time `json:"-"`

	// ExpiresIn is the token lifetime in seconds (from API response)
	ExpiresIn int64 `json:"expires_in"`
}

// TokenManager handles token lifecycle management
type TokenManager struct {
	config     AuthConfig
	baseURL    string
	httpClient *http.Client

	mu           sync.RWMutex
	currentToken *TokenInfo
}

// NewTokenManager creates a new token manager
func NewTokenManager(baseURL string, config AuthConfig, httpClient *http.Client) *TokenManager {
	if config.TokenRefreshBuffer == 0 {
		config.TokenRefreshBuffer = 5 * time.Minute
	}

	tm := &TokenManager{
		config:     config,
		baseURL:    baseURL,
		httpClient: httpClient,
	}

	// If using static token mode, initialize with provided token
	if config.Mode == AuthModeToken && config.Token != "" {
		tm.currentToken = &TokenInfo{
			AccessToken: config.Token,
			// Static tokens don't expire (or we don't know when)
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
		}
	}

	return tm
}

// GetToken returns a valid token, refreshing if necessary
func (tm *TokenManager) GetToken(ctx context.Context) (string, error) {
	// For static token mode, always return the configured token
	if tm.config.Mode == AuthModeToken {
		return tm.config.Token, nil
	}

	tm.mu.RLock()
	token := tm.currentToken
	tm.mu.RUnlock()

	// Check if we have a valid token
	if token != nil && time.Now().Add(tm.config.TokenRefreshBuffer).Before(token.ExpiresAt) {
		return token.AccessToken, nil
	}

	// Need to refresh token
	return tm.refreshToken(ctx)
}

// refreshToken acquires a new token from the Aqua API
func (tm *TokenManager) refreshToken(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring lock
	if tm.currentToken != nil && time.Now().Add(tm.config.TokenRefreshBuffer).Before(tm.currentToken.ExpiresAt) {
		return tm.currentToken.AccessToken, nil
	}

	// Prepare login request
	loginReq := struct {
		ID       string `json:"id"`
		Password string `json:"password"`
	}{
		ID:       tm.config.Username,
		Password: tm.config.Password,
	}

	body, err := json.Marshal(loginReq)
	if err != nil {
		return "", fmt.Errorf("marshaling login request: %w", err)
	}

	apiURL, err := url.JoinPath(tm.baseURL, "api", "v1", "login")
	if err != nil {
		return "", fmt.Errorf("building login URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := tm.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing login request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenInfo TokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&tokenInfo); err != nil {
		return "", fmt.Errorf("decoding login response: %w", err)
	}

	// Calculate expiration time
	if tokenInfo.ExpiresIn > 0 {
		tokenInfo.ExpiresAt = time.Now().Add(time.Duration(tokenInfo.ExpiresIn) * time.Second)
	} else {
		// Default to 1 hour if not specified
		tokenInfo.ExpiresAt = time.Now().Add(1 * time.Hour)
	}

	tm.currentToken = &tokenInfo
	return tokenInfo.AccessToken, nil
}

// SignRequest adds HMAC256 signature to a request
// The signature is computed over: HTTP_METHOD + URL + TIMESTAMP + REQUEST_BODY
func (tm *TokenManager) SignRequest(req *http.Request, body []byte) error {
	if tm.config.HMACSecret == "" {
		return nil // No signing configured
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Build the string to sign
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		req.Method,
		req.URL.String(),
		timestamp,
		string(body),
	)

	// Compute HMAC256 signature
	signature := computeHMAC256(stringToSign, tm.config.HMACSecret)

	// Add signature headers
	req.Header.Set("X-Aqua-Timestamp", timestamp)
	req.Header.Set("X-Aqua-Signature", signature)

	return nil
}

// computeHMAC256 computes HMAC-SHA256 signature
func computeHMAC256(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateHMACSignature validates an incoming HMAC signature
// This can be useful for webhook validation
func ValidateHMACSignature(message, signature, secret string) bool {
	expectedSig := computeHMAC256(message, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}
