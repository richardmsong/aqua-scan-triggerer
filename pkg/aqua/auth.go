package aqua

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// Token is the API token for authentication
	Token string

	// HMACSecret is used for HMAC256 request signing (optional)
	HMACSecret string
}

// TokenManager handles token and request signing
type TokenManager struct {
	config  AuthConfig
	verbose bool
}

// NewTokenManager creates a new token manager
func NewTokenManager(baseURL string, config AuthConfig, httpClient *http.Client, verbose bool) *TokenManager {
	return &TokenManager{
		config:  config,
		verbose: verbose,
	}
}

// GetToken returns the configured token
func (tm *TokenManager) GetToken() string {
	token := tm.config.Token
	if tm.verbose {
		if token == "" {
			log.Printf("[AUTH] GetToken: token is EMPTY")
		} else {
			masked := token[:min(6, len(token))] + "..."
			log.Printf("[AUTH] GetToken: using token %s (len=%d)", masked, len(token))
		}
	}
	return token
}

// SignRequest adds HMAC256 signature to a request
// The signature is computed over: timestamp + method + path + body (concatenated without separators)
// This matches the Aqua CSPM API token signing format
func (tm *TokenManager) SignRequest(req *http.Request, body []byte) error {
	if tm.config.HMACSecret == "" {
		if tm.verbose {
			log.Printf("[AUTH] SignRequest: HMAC signing not configured (no secret)")
		}
		return nil // No signing configured
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Build the string to sign: timestamp + method + path + body
	// Using the path only (not full URL) as per Aqua API spec
	stringToSign := fmt.Sprintf("%s%s%s%s",
		timestamp,
		req.Method,
		req.URL.Path,
		string(body),
	)

	// Compute HMAC256 signature
	signature := computeHMAC256(stringToSign, tm.config.HMACSecret)

	if tm.verbose {
		log.Printf("[AUTH] SignRequest: %s %s", req.Method, req.URL.Path)
		log.Printf("[AUTH] SignRequest: timestamp=%s", timestamp)
		log.Printf("[AUTH] SignRequest: signature=%s... (len=%d)", signature[:min(16, len(signature))], len(signature))
	}

	// Add signature headers (per Aqua API spec)
	req.Header.Set("X-API-Key", tm.config.Token)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

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
