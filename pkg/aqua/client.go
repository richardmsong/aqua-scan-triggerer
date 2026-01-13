package aqua

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// DefaultCacheTTL is the default time-to-live for cached registry data
const DefaultCacheTTL = 1 * time.Hour

// ScanStatus represents the status returned by Aqua
type ScanStatus string

const (
	StatusNotFound ScanStatus = "not_found"
	StatusFound    ScanStatus = "found"
)

// ScanResult contains the results from Aqua
// With v2 API, we only care about whether the image was found (scanned) or not
type ScanResult struct {
	Status ScanStatus
	Image  string
	Digest string
}

// Registry represents an Aqua registry configuration
type Registry struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Description   string   `json:"description"`
	URL           string   `json:"url"`
	Prefixes      []string `json:"prefixes"`
	DefaultPrefix string   `json:"default_prefix"`
}

// RegistriesResponse is the response from GET /api/v2/registries
type RegistriesResponse struct {
	Count    int        `json:"count"`
	Page     int        `json:"page"`
	PageSize int        `json:"pagesize"`
	Result   []Registry `json:"result"`
}

// Client interface for Aqua operations
type Client interface {
	// GetScanResult retrieves existing scan results for an image
	GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error)

	// TriggerScan initiates a new scan for an image
	TriggerScan(ctx context.Context, image, digest string) (string, error)

	// GetRegistries retrieves all configured registries from Aqua
	GetRegistries(ctx context.Context) ([]Registry, error)

	// FindRegistryByPrefix finds the Aqua registry name that matches a container registry prefix
	FindRegistryByPrefix(ctx context.Context, containerRegistry string) (string, error)
}

// RegistryMirror defines a mapping from a source registry to its mirror.
// This is useful in airgapped environments where public registries are mirrored
// to internal registries (e.g., Artifactory, Harbor).
type RegistryMirror struct {
	// Source is the original registry host (e.g., "docker.io", "gcr.io")
	Source string `json:"source"`

	// Mirror is the mirrored registry host (e.g., "artifactory.internal.com/docker-remote")
	Mirror string `json:"mirror"`
}

// Config holds Aqua client configuration
type Config struct {
	// BaseURL is the Aqua server URL
	BaseURL string

	// APIKey for authentication
	APIKey string

	// Registry is the Aqua registry name to use for scans
	Registry string

	// Timeout for API calls
	Timeout time.Duration

	// InsecureSkipVerify disables TLS verification (not recommended for production)
	InsecureSkipVerify bool

	// CacheTTL is the time-to-live for cached registry data (default: 1 hour)
	CacheTTL time.Duration

	// RegistryMirrors defines mappings from source registries to their mirrors.
	// When an image from a source registry is encountered, the registry prefix
	// will be replaced with the mirror before looking up the Aqua registry.
	// Example: {"source": "docker.io", "mirror": "artifactory.internal.com/docker-remote"}
	RegistryMirrors []RegistryMirror
}

// registryCache holds cached registry data with timestamp
type registryCache struct {
	registries []Registry
	fetchedAt  time.Time
}

type aquaClient struct {
	config     Config
	httpClient *http.Client

	// Cache for registries
	cacheMu sync.RWMutex
	cache   *registryCache
}

// NewClient creates a new Aqua client
func NewClient(config Config) Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = DefaultCacheTTL
	}

	return &aquaClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// applyMirrorMapping checks if the container registry has a mirror configured
// and returns the mirrored registry prefix for Aqua lookup.
// The full mirror URL (including any path) is used as the registry prefix to search for in Aqua.
// For example, if docker.io is mirrored to artifactory.internal.com/docker-remote,
// the Aqua registry should have prefix "artifactory.internal.com/docker-remote".
// The image name is NOT modified - it stays as "library/nginx".
func applyMirrorMapping(containerRegistry, imageName string, mirrors []RegistryMirror) (mirroredRegistry, mirroredImageName string) {
	// Normalize for comparison (handle docker.io vs index.docker.io)
	normalizedRegistry := normalizeRegistryName(containerRegistry)

	for _, mirror := range mirrors {
		normalizedSource := normalizeRegistryName(mirror.Source)
		if normalizedRegistry == normalizedSource {
			// Return the full mirror URL as the registry prefix for Aqua lookup
			// The image name stays unchanged
			mirrorValue := strings.TrimPrefix(mirror.Mirror, "https://")
			mirrorValue = strings.TrimPrefix(mirrorValue, "http://")
			mirrorValue = strings.TrimSuffix(mirrorValue, "/")
			return mirrorValue, imageName
		}
	}

	// No mirror found, return original values
	return containerRegistry, imageName
}

// normalizeRegistryName normalizes registry names for comparison.
// Handles docker.io vs index.docker.io equivalence.
func normalizeRegistryName(registry string) string {
	registry = strings.TrimPrefix(registry, "https://")
	registry = strings.TrimPrefix(registry, "http://")
	registry = strings.TrimSuffix(registry, "/")

	// Normalize Docker Hub variations
	switch registry {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return registry
}

// parseMirrorURL parses a mirror URL into host and path components.
// For example, "artifactory.internal.com/docker-remote" returns
// ("artifactory.internal.com", "docker-remote").
func parseMirrorURL(mirror string) (host, path string) {
	mirror = strings.TrimPrefix(mirror, "https://")
	mirror = strings.TrimPrefix(mirror, "http://")
	mirror = strings.TrimSuffix(mirror, "/")

	// Find the first slash to separate host from path
	if idx := strings.Index(mirror, "/"); idx != -1 {
		return mirror[:idx], mirror[idx+1:]
	}
	return mirror, ""
}

// parseImageReference extracts container registry and image parts from a full image reference
// using go-containerregistry/pkg/name for proper parsing.
// Example: "richardmsong/jfrog-token-exchanger" with digest "sha256:abc123..."
// returns container registry (e.g., "ghcr.io"), image name, and @sha256:... as tag
func parseImageReference(image, digest string) (containerRegistry, imageName, tag string, err error) {
	// Parse the image reference using go-containerregistry
	ref, parseErr := name.ParseReference(image)
	if parseErr != nil {
		return "", "", "", fmt.Errorf("parsing image reference: %w", parseErr)
	}

	// Extract the container registry from the parsed reference (e.g., "ghcr.io", "docker.io")
	containerRegistry = ref.Context().RegistryStr()

	// Get the repository path (without registry)
	imageName = ref.Context().RepositoryStr()

	// Tag is the digest prefixed with @
	tag = "@" + digest

	return containerRegistry, imageName, tag, nil
}

// parseImageReferenceWithMirrors extracts container registry and image parts,
// applying any configured registry mirrors to resolve the actual registry to query.
func parseImageReferenceWithMirrors(image, digest string, mirrors []RegistryMirror) (containerRegistry, imageName, tag string, err error) {
	containerRegistry, imageName, tag, err = parseImageReference(image, digest)
	if err != nil {
		return "", "", "", err
	}

	// Apply mirror mapping if configured
	if len(mirrors) > 0 {
		containerRegistry, imageName = applyMirrorMapping(containerRegistry, imageName, mirrors)
	}

	return containerRegistry, imageName, tag, nil
}

func (c *aquaClient) GetScanResult(ctx context.Context, image, digest string) (*ScanResult, error) {
	// GET /api/v2/images/{registry}/{image}/{tag}
	// where tag is @sha256:...
	// If not 404, consider it scanned/passed

	containerRegistry, imageName, tag, err := parseImageReferenceWithMirrors(image, digest, c.config.RegistryMirrors)
	if err != nil {
		return nil, err
	}

	// Look up the Aqua registry name from the container registry
	aquaRegistry, err := c.FindRegistryByPrefix(ctx, containerRegistry)
	if err != nil {
		return nil, fmt.Errorf("finding Aqua registry for %q: %w", containerRegistry, err)
	}

	// Build URL using url.JoinPath for proper URL construction
	apiURL, err := url.JoinPath(c.config.BaseURL, "api", "v2", "images", aquaRegistry, imageName, tag)
	if err != nil {
		return nil, fmt.Errorf("building API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// 404 means not scanned yet
	if resp.StatusCode == http.StatusNotFound {
		return &ScanResult{
			Status: StatusNotFound,
			Image:  image,
			Digest: digest,
		}, nil
	}

	// Any other non-error response means the image has been scanned
	// We don't care about the enforcement - Aqua enforcer handles that
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &ScanResult{
			Status: StatusFound,
			Image:  image,
			Digest: digest,
		}, nil
	}

	// Read response body for error details
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
}

// triggerScanRequest is the request body for POST /api/v2/images
type triggerScanRequest struct {
	Registry string `json:"registry"`
	Image    string `json:"image"`
}

func (c *aquaClient) TriggerScan(ctx context.Context, image, digest string) (string, error) {
	// POST /api/v2/images
	// Body: {"registry": "...", "image": "imagename@sha256:..."}

	containerRegistry, imageName, _, err := parseImageReferenceWithMirrors(image, digest, c.config.RegistryMirrors)
	if err != nil {
		return "", err
	}

	// Look up the Aqua registry name from the container registry
	aquaRegistry, err := c.FindRegistryByPrefix(ctx, containerRegistry)
	if err != nil {
		return "", fmt.Errorf("finding Aqua registry for %q: %w", containerRegistry, err)
	}

	// Build the image reference with digest for the API
	// Format: imagename@sha256:...
	imageWithDigest := imageName + "@" + digest

	reqBody := triggerScanRequest{
		Registry: aquaRegistry,
		Image:    imageWithDigest,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request body: %w", err)
	}

	// Build URL using url.JoinPath for proper URL construction
	apiURL, err := url.JoinPath(c.config.BaseURL, "api", "v2", "images")
	if err != nil {
		return "", fmt.Errorf("building API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// 201 Created is the expected response
	if resp.StatusCode == http.StatusCreated {
		// Return a composite ID for tracking (registry/image@digest)
		return fmt.Sprintf("%s/%s", aquaRegistry, imageWithDigest), nil
	}

	// Read response body for error details
	respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBodyBytes))
}

func (c *aquaClient) GetRegistries(ctx context.Context) ([]Registry, error) {
	// Check cache first with read lock
	c.cacheMu.RLock()
	if c.cache != nil && time.Since(c.cache.fetchedAt) < c.config.CacheTTL {
		registries := c.cache.registries
		c.cacheMu.RUnlock()
		return registries, nil
	}
	c.cacheMu.RUnlock()

	// Cache miss or expired, fetch from API
	return c.fetchRegistries(ctx)
}

// fetchRegistries fetches registries from the API and updates the cache
func (c *aquaClient) fetchRegistries(ctx context.Context) ([]Registry, error) {
	// GET /api/v2/registries
	// Returns all configured registries in Aqua

	apiURL, err := url.JoinPath(c.config.BaseURL, "api", "v2", "registries")
	if err != nil {
		return nil, fmt.Errorf("building API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var registriesResp RegistriesResponse
	if err := json.NewDecoder(resp.Body).Decode(&registriesResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Update cache with write lock
	c.cacheMu.Lock()
	c.cache = &registryCache{
		registries: registriesResp.Result,
		fetchedAt:  time.Now(),
	}
	c.cacheMu.Unlock()

	return registriesResp.Result, nil
}

// refreshCache forces a cache refresh by fetching registries from the API
func (c *aquaClient) refreshCache(ctx context.Context) ([]Registry, error) {
	return c.fetchRegistries(ctx)
}

func (c *aquaClient) FindRegistryByPrefix(ctx context.Context, containerRegistry string) (string, error) {
	// If a default registry is configured, use it
	if c.config.Registry != "" {
		return c.config.Registry, nil
	}

	// First try with cached registries
	registries, err := c.GetRegistries(ctx)
	if err != nil {
		return "", fmt.Errorf("getting registries: %w", err)
	}

	if name := c.findRegistryInList(containerRegistry, registries); name != "" {
		return name, nil
	}

	// Not found in cache - refresh cache and try again in case it's stale
	registries, err = c.refreshCache(ctx)
	if err != nil {
		return "", fmt.Errorf("refreshing registry cache: %w", err)
	}

	if name := c.findRegistryInList(containerRegistry, registries); name != "" {
		return name, nil
	}

	return "", fmt.Errorf("no Aqua registry found for container registry %q", containerRegistry)
}

// findRegistryInList searches for a matching registry in the given list
func (c *aquaClient) findRegistryInList(containerRegistry string, registries []Registry) string {
	// Normalize the container registry for comparison
	normalizedRegistry := strings.TrimPrefix(containerRegistry, "https://")
	normalizedRegistry = strings.TrimPrefix(normalizedRegistry, "http://")
	normalizedRegistry = strings.TrimSuffix(normalizedRegistry, "/")

	// Search for a registry whose prefixes contain the container registry
	for _, reg := range registries {
		for _, prefix := range reg.Prefixes {
			// Normalize the prefix for comparison
			normalizedPrefix := strings.TrimPrefix(prefix, "https://")
			normalizedPrefix = strings.TrimPrefix(normalizedPrefix, "http://")
			normalizedPrefix = strings.TrimSuffix(normalizedPrefix, "/")

			// Check if the container registry matches or starts with the prefix
			if normalizedRegistry == normalizedPrefix ||
				strings.HasPrefix(normalizedRegistry, normalizedPrefix+"/") ||
				strings.HasPrefix(normalizedPrefix, normalizedRegistry) {
				return reg.Name
			}
		}
	}

	return ""
}
