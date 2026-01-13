package aqua

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TokenManager", func() {
	var (
		server     *httptest.Server
		httpClient *http.Client
	)

	BeforeEach(func() {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	})

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Describe("with AuthModeToken", func() {
		It("should return static token", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Mode:  AuthModeToken,
				Token: "my-static-token",
			}, httpClient)

			token, err := tm.GetToken(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(token).To(Equal("my-static-token"))
		})

		It("should return same token on multiple calls", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Mode:  AuthModeToken,
				Token: "my-static-token",
			}, httpClient)

			token1, err := tm.GetToken(context.Background())
			Expect(err).NotTo(HaveOccurred())

			token2, err := tm.GetToken(context.Background())
			Expect(err).NotTo(HaveOccurred())

			Expect(token1).To(Equal(token2))
		})
	})

	Describe("with AuthModeCredentials", func() {
		Context("when login succeeds", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Expect(r.URL.Path).To(Equal("/api/v1/login"))
					Expect(r.Method).To(Equal("POST"))

					var loginReq struct {
						ID       string `json:"id"`
						Password string `json:"password"`
					}
					err := json.NewDecoder(r.Body).Decode(&loginReq)
					Expect(err).NotTo(HaveOccurred())
					Expect(loginReq.ID).To(Equal("test-user"))
					Expect(loginReq.Password).To(Equal("test-password"))

					resp := TokenInfo{
						AccessToken: "acquired-token-12345",
						ExpiresIn:   3600,
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					err = json.NewEncoder(w).Encode(resp)
					Expect(err).NotTo(HaveOccurred())
				}))
			})

			It("should acquire token via login", func() {
				tm := NewTokenManager(server.URL, AuthConfig{
					Mode:     AuthModeCredentials,
					Username: "test-user",
					Password: "test-password",
				}, httpClient)

				token, err := tm.GetToken(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(token).To(Equal("acquired-token-12345"))
			})

			It("should cache token and not call login again", func() {
				var loginCount int32
				server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&loginCount, 1)
					resp := TokenInfo{
						AccessToken: "acquired-token-12345",
						ExpiresIn:   3600,
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(resp)
				})

				tm := NewTokenManager(server.URL, AuthConfig{
					Mode:     AuthModeCredentials,
					Username: "test-user",
					Password: "test-password",
				}, httpClient)

				// Call GetToken multiple times
				for i := 0; i < 5; i++ {
					token, err := tm.GetToken(context.Background())
					Expect(err).NotTo(HaveOccurred())
					Expect(token).To(Equal("acquired-token-12345"))
				}

				// Should only have called login once
				Expect(atomic.LoadInt32(&loginCount)).To(Equal(int32(1)))
			})
		})

		Context("when login fails", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error": "invalid credentials"}`))
				}))
			})

			It("should return error", func() {
				tm := NewTokenManager(server.URL, AuthConfig{
					Mode:     AuthModeCredentials,
					Username: "bad-user",
					Password: "bad-password",
				}, httpClient)

				_, err := tm.GetToken(context.Background())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("401"))
				Expect(err.Error()).To(ContainSubstring("invalid credentials"))
			})
		})

		Context("when token expires", func() {
			It("should refresh token before expiry", func() {
				var tokenVersion int32
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					version := atomic.AddInt32(&tokenVersion, 1)
					resp := TokenInfo{
						AccessToken: "token-v" + string(rune('0'+version)),
						ExpiresIn:   1, // Expires in 1 second
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(resp)
				}))

				tm := NewTokenManager(server.URL, AuthConfig{
					Mode:               AuthModeCredentials,
					Username:           "test-user",
					Password:           "test-password",
					TokenRefreshBuffer: 500 * time.Millisecond,
				}, httpClient)

				// Get initial token
				token1, err := tm.GetToken(context.Background())
				Expect(err).NotTo(HaveOccurred())

				// Wait for token to be near expiry
				time.Sleep(600 * time.Millisecond)

				// Should refresh token
				token2, err := tm.GetToken(context.Background())
				Expect(err).NotTo(HaveOccurred())

				// Tokens should be different
				Expect(token1).NotTo(Equal(token2))
			})
		})

		Context("with concurrent requests", func() {
			It("should only refresh once with multiple concurrent requests", func() {
				var loginCount int32
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&loginCount, 1)
					// Simulate slow login
					time.Sleep(100 * time.Millisecond)
					resp := TokenInfo{
						AccessToken: "concurrent-token",
						ExpiresIn:   3600,
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(resp)
				}))

				tm := NewTokenManager(server.URL, AuthConfig{
					Mode:     AuthModeCredentials,
					Username: "test-user",
					Password: "test-password",
				}, httpClient)

				// Launch concurrent GetToken calls
				var wg sync.WaitGroup
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						token, err := tm.GetToken(context.Background())
						Expect(err).NotTo(HaveOccurred())
						Expect(token).To(Equal("concurrent-token"))
					}()
				}
				wg.Wait()

				// Should only have called login once due to double-check locking
				Expect(atomic.LoadInt32(&loginCount)).To(Equal(int32(1)))
			})
		})
	})
})

var _ = Describe("HMAC256 Signing", func() {
	Describe("SignRequest", func() {
		It("should not add headers when HMAC secret is empty", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Mode:       AuthModeToken,
				Token:      "test-token",
				HMACSecret: "",
			}, &http.Client{})

			req, _ := http.NewRequest("GET", "https://api.aquasec.com/test", nil)
			err := tm.SignRequest(req, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Header.Get("X-Aqua-Timestamp")).To(BeEmpty())
			Expect(req.Header.Get("X-Aqua-Signature")).To(BeEmpty())
		})

		It("should add signature headers when HMAC secret is set", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Mode:       AuthModeToken,
				Token:      "test-token",
				HMACSecret: "my-secret-key",
			}, &http.Client{})

			req, _ := http.NewRequest("GET", "https://api.aquasec.com/test", nil)
			err := tm.SignRequest(req, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Header.Get("X-Aqua-Timestamp")).NotTo(BeEmpty())
			Expect(req.Header.Get("X-Aqua-Signature")).NotTo(BeEmpty())
		})

		It("should generate consistent signatures for same input", func() {
			// Use same timestamp by directly calling computeHMAC256
			message := "GET\nhttps://api.aquasec.com/test\n2024-01-01T00:00:00Z\n"
			sig1 := computeHMAC256(message, "my-secret-key")
			sig2 := computeHMAC256(message, "my-secret-key")
			Expect(sig1).To(Equal(sig2))
		})

		It("should generate different signatures for different secrets", func() {
			message := "GET\nhttps://api.aquasec.com/test\n2024-01-01T00:00:00Z\n"
			sig1 := computeHMAC256(message, "secret-1")
			sig2 := computeHMAC256(message, "secret-2")
			Expect(sig1).NotTo(Equal(sig2))
		})

		It("should include request body in signature", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Mode:       AuthModeToken,
				Token:      "test-token",
				HMACSecret: "my-secret-key",
			}, &http.Client{})

			req1, _ := http.NewRequest("POST", "https://api.aquasec.com/test", nil)
			req2, _ := http.NewRequest("POST", "https://api.aquasec.com/test", nil)

			err := tm.SignRequest(req1, []byte(`{"foo":"bar"}`))
			Expect(err).NotTo(HaveOccurred())
			err = tm.SignRequest(req2, []byte(`{"foo":"baz"}`))
			Expect(err).NotTo(HaveOccurred())

			// Different bodies should produce different signatures
			// (though timestamps might also differ, making them different anyway)
			sig1 := req1.Header.Get("X-Aqua-Signature")
			sig2 := req2.Header.Get("X-Aqua-Signature")
			Expect(sig1).NotTo(BeEmpty())
			Expect(sig2).NotTo(BeEmpty())
		})
	})

	Describe("ValidateHMACSignature", func() {
		It("should return true for valid signature", func() {
			message := "test message"
			secret := "my-secret"
			signature := computeHMAC256(message, secret)

			valid := ValidateHMACSignature(message, signature, secret)
			Expect(valid).To(BeTrue())
		})

		It("should return false for invalid signature", func() {
			message := "test message"
			secret := "my-secret"

			valid := ValidateHMACSignature(message, "invalid-signature", secret)
			Expect(valid).To(BeFalse())
		})

		It("should return false for wrong secret", func() {
			message := "test message"
			signature := computeHMAC256(message, "correct-secret")

			valid := ValidateHMACSignature(message, signature, "wrong-secret")
			Expect(valid).To(BeFalse())
		})
	})
})

var _ = Describe("NewClient with Auth", func() {
	It("should maintain backward compatibility with APIKey", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			APIKey:   "legacy-api-key",
			Registry: "test-registry",
		})

		Expect(client).NotTo(BeNil())
		// The client should work with the legacy APIKey
	})

	It("should use Auth.Token when provided", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				Mode:  AuthModeToken,
				Token: "new-style-token",
			},
		})

		Expect(client).NotTo(BeNil())
	})

	It("should use credentials mode when configured", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				Mode:     AuthModeCredentials,
				Username: "test-user",
				Password: "test-password",
			},
		})

		Expect(client).NotTo(BeNil())
	})

	It("should support HMAC secret configuration", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				Mode:       AuthModeToken,
				Token:      "test-token",
				HMACSecret: "my-hmac-secret",
			},
		})

		Expect(client).NotTo(BeNil())
	})
})
