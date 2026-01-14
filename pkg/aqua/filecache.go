package aqua

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultCacheDir is the default directory for cache files
	DefaultCacheDir = "/tmp/aqua-scan-triggerer"
	// DefaultCacheFile is the default filename for the registry cache
	DefaultCacheFile = "registries.json"
)

// FileCacheConfig holds configuration for the file-based cache
type FileCacheConfig struct {
	// CacheDir is the directory where cache files are stored
	// Default: /tmp/aqua-scan-triggerer
	CacheDir string

	// CacheFile is the filename for the cache file
	// Default: registries.json
	CacheFile string

	// TTL is the time-to-live for cached data
	TTL time.Duration

	// Enabled determines if file caching is enabled
	// Default: true
	Enabled bool
}

// fileCacheData represents the data structure stored in the cache file
type fileCacheData struct {
	Registries []Registry `json:"registries"`
	FetchedAt  time.Time  `json:"fetched_at"`
	Version    string     `json:"version"`
}

// FileCacheResult holds the result of a cache read operation
type FileCacheResult struct {
	Registries []Registry
	FetchedAt  time.Time
}

// FileCache provides file-based caching for registry data
type FileCache struct {
	config FileCacheConfig
	mu     sync.Mutex
}

// NewFileCache creates a new file-based cache
func NewFileCache(config FileCacheConfig) *FileCache {
	if config.CacheDir == "" {
		config.CacheDir = DefaultCacheDir
	}
	if config.CacheFile == "" {
		config.CacheFile = DefaultCacheFile
	}
	if config.TTL == 0 {
		config.TTL = DefaultCacheTTL
	}

	return &FileCache{
		config: config,
	}
}

// cacheFilePath returns the full path to the cache file
func (fc *FileCache) cacheFilePath() string {
	return filepath.Join(fc.config.CacheDir, fc.config.CacheFile)
}

// ensureCacheDir creates the cache directory if it doesn't exist
func (fc *FileCache) ensureCacheDir() error {
	return os.MkdirAll(fc.config.CacheDir, 0755)
}

// Get retrieves registries from the file cache if valid
// Returns nil if cache is not present or expired
// The result includes the FetchedAt timestamp for proper TTL tracking
func (fc *FileCache) Get() (*FileCacheResult, error) {
	if !fc.config.Enabled {
		return nil, nil
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	data, err := os.ReadFile(fc.cacheFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Cache file doesn't exist
		}
		return nil, fmt.Errorf("reading cache file: %w", err)
	}

	var cacheData fileCacheData
	if err := json.Unmarshal(data, &cacheData); err != nil {
		// Invalid cache file, treat as cache miss
		return nil, nil
	}

	// Check if cache is expired
	if time.Since(cacheData.FetchedAt) > fc.config.TTL {
		return nil, nil // Cache expired
	}

	return &FileCacheResult{
		Registries: cacheData.Registries,
		FetchedAt:  cacheData.FetchedAt,
	}, nil
}

// Set stores registries in the file cache
func (fc *FileCache) Set(registries []Registry) error {
	if !fc.config.Enabled {
		return nil
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	if err := fc.ensureCacheDir(); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	cacheData := fileCacheData{
		Registries: registries,
		FetchedAt:  time.Now(),
		Version:    "1",
	}

	data, err := json.MarshalIndent(cacheData, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cache data: %w", err)
	}

	// Write to a temporary file first, then rename for atomicity
	tmpFile := fc.cacheFilePath() + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("writing temporary cache file: %w", err)
	}

	if err := os.Rename(tmpFile, fc.cacheFilePath()); err != nil {
		// Clean up temporary file on rename failure
		_ = os.Remove(tmpFile)
		return fmt.Errorf("renaming cache file: %w", err)
	}

	return nil
}

// Clear removes the cache file
func (fc *FileCache) Clear() error {
	if !fc.config.Enabled {
		return nil
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	err := os.Remove(fc.cacheFilePath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cache file: %w", err)
	}
	return nil
}

// IsExpired checks if the cache has expired without loading all data
func (fc *FileCache) IsExpired() (bool, error) {
	if !fc.config.Enabled {
		return true, nil
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	info, err := os.Stat(fc.cacheFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // No cache file = expired
		}
		return true, fmt.Errorf("checking cache file: %w", err)
	}

	// Quick check based on file modification time
	// Note: This is a rough check; actual expiration is based on FetchedAt in the file
	if time.Since(info.ModTime()) > fc.config.TTL {
		return true, nil
	}

	return false, nil
}

// GetCachePath returns the path to the cache file (useful for debugging/logging)
func (fc *FileCache) GetCachePath() string {
	return fc.cacheFilePath()
}
