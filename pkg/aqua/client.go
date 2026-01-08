package aqua

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ScanStatus represents the status returned by Aqua
type ScanStatus string

const (
	StatusNotFound  ScanStatus = "not_found"
	StatusQueued    ScanStatus = "queued"
	StatusScanning  ScanStatus = "scanning"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

// ScanResult contains the results from Aqua
type ScanResult struct {
	ScanID           string
	Status           ScanStatus
	Image            string
	Digest           string
	Critical         int
	High             int
	Medium           int
	Low              int
	CompliancePassed bool
	ScanTime         time.Time
}

// Client interface for Aqua operations
type Client interface {
	// GetScanResult retrieves existing scan results for an image
	GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error)

	// TriggerScan initiates a new scan for an image
	TriggerScan(ctx context.Context, image, digest string) (string, error)

	// GetScanStatus checks the status of a specific scan
	GetScanStatus(ctx context.Context, scanID string) (*ScanResult, error)
}

// Config holds Aqua client configuration
type Config struct {
	// BaseURL is the Aqua server URL
	BaseURL string

	// APIKey for authentication
	APIKey string

	// Timeout for API calls
	Timeout time.Duration

	// InsecureSkipVerify disables TLS verification (not recommended for production)
	InsecureSkipVerify bool
}

type aquaClient struct {
	config     Config
	httpClient *http.Client
}

// NewClient creates a new Aqua client
func NewClient(config Config) Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &aquaClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

func (c *aquaClient) GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error) {
	// Implementation will call Aqua's API
	// GET /api/v2/images/{registry}/{repo}/{tag}/scan_results
	// or GET /api/v2/images/by_digest/{digest}

	url := fmt.Sprintf("%s/api/v2/images/by_digest/%s", c.config.BaseURL, digest)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ScanResult{Status: StatusNotFound}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

func (c *aquaClient) TriggerScan(ctx context.Context, image, digest string) (string, error) {
	// Implementation will call Aqua's API to trigger a scan
	// POST /api/v2/images/scan

	// Return scan ID for tracking
	return "", fmt.Errorf("not implemented - implement based on your Aqua API version")
}

func (c *aquaClient) GetScanStatus(ctx context.Context, scanID string) (*ScanResult, error) {
	// Implementation will check scan status
	// GET /api/v2/scans/{scanID}

	return nil, fmt.Errorf("not implemented - implement based on your Aqua API version")
}
