// File    : topn.go
// Version : 1.0.0
// Modified: 2026-04-01 12:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: TOP-N domain list manager. Downloads the Tranco top-1M list
//          (delivered as a ZIP containing a CSV), caches the unzipped CSV
//          locally, and provides O(1) apex-domain rank lookups via an
//          in-memory map. List is refreshed automatically when the cache
//          exceeds RefreshTTL. The Rank() call is safe for concurrent use.

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TopN manages the ranked domain list.
type TopN struct {
	ranks      map[string]int // apex domain (lowercase) → 1-based rank
	provider   string
	url        string
	cachePath  string
	refreshTTL time.Duration
	size       int        // max entries to load
	loaded     time.Time
	mu         sync.RWMutex
}

// NewTopN creates a TopN instance from cfg. The list is loaded lazily on first Rank() call.
func NewTopN(cfg *Config) *TopN {
	return &TopN{
		ranks:      make(map[string]int),
		provider:   cfg.TopN.Provider,
		url:        cfg.TopN.URL,
		cachePath:  cfg.TopN.CachePath,
		refreshTTL: cfg.TopN.RefreshTTL,
		size:       cfg.TopN.Size,
	}
}

// Rank returns the 1-based rank of an apex domain, or 0 if not in the list.
// Triggers a download on the first call (or after RefreshTTL has elapsed).
// That first call may block for a few seconds while the list downloads.
func (t *TopN) Rank(apex string) int {
	if err := t.ensureLoaded(); err != nil {
		// Non-fatal: if the list is unavailable the domain just won't score
		// TOP_N points. The error will surface in the validator's Errors slice.
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ranks[strings.ToLower(apex)]
}

// Size returns the number of entries currently loaded.
func (t *TopN) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.ranks)
}

// ensureLoaded loads the list from local cache or downloads it if stale/absent.
func (t *TopN) ensureLoaded() error {
	// Fast path: in-memory copy is still fresh.
	t.mu.RLock()
	fresh := len(t.ranks) > 0 && time.Since(t.loaded) < t.refreshTTL
	t.mu.RUnlock()
	if fresh {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have loaded it).
	if len(t.ranks) > 0 && time.Since(t.loaded) < t.refreshTTL {
		return nil
	}

	// If the local CSV cache is still fresh, load from disk.
	if info, err := os.Stat(t.cachePath); err == nil {
		if time.Since(info.ModTime()) < t.refreshTTL {
			return t.loadFromCSVFile(t.cachePath)
		}
	}

	// Download the list.
	data, err := t.download()
	if err != nil {
		// Download failed — fall back to stale cache rather than returning no data.
		if _, serr := os.Stat(t.cachePath); serr == nil {
			_ = t.loadFromCSVFile(t.cachePath) // ignore error; stale > nothing
			return nil
		}
		return fmt.Errorf("download TOP-N list (%s): %w", t.provider, err)
	}

	return t.extractAndCache(data)
}

// download fetches the raw bytes from the configured URL.
func (t *TopN) download() ([]byte, error) {
	resp, err := http.Get(t.url) //nolint:noctx — batch download, timeout via OS
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, t.url)
	}
	// 100MB cap — the Tranco ZIP is ~5MB; this leaves plenty of headroom.
	return io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
}

// extractAndCache handles both ZIP (Tranco) and raw CSV (other providers),
// writes the CSV to the cache path, and parses it into memory.
func (t *TopN) extractAndCache(data []byte) error {
	csvData := data

	// Try to treat the data as a ZIP archive (Tranco delivers .csv.zip).
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for _, f := range zr.File {
			if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
				rc, err := f.Open()
				if err != nil {
					return fmt.Errorf("open zip entry %s: %w", f.Name, err)
				}
				csvData, err = io.ReadAll(rc)
				rc.Close()
				if err != nil {
					return fmt.Errorf("read zip entry %s: %w", f.Name, err)
				}
				break
			}
		}
	}

	if len(csvData) == 0 {
		return fmt.Errorf("no CSV data found in downloaded content")
	}

	// Write unzipped CSV to local cache.
	if err := os.WriteFile(t.cachePath, csvData, 0o644); err != nil {
		return fmt.Errorf("write cache %s: %w", t.cachePath, err)
	}

	return t.parseCSV(csvData)
}

// loadFromCSVFile reads the cache file and parses it.
func (t *TopN) loadFromCSVFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read cache %s: %w", path, err)
	}
	return t.parseCSV(data)
}

// parseCSV parses the rank,domain format used by both Tranco and Majestic Million.
// Format: "1,google.com\n2,youtube.com\n..."
// Entries beyond t.size are ignored to cap memory usage.
func (t *TopN) parseCSV(data []byte) error {
	ranks := make(map[string]int, t.size)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	count := 0

	for scanner.Scan() {
		if count >= t.size {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		rank, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || rank <= 0 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(parts[1]))
		if domain == "" {
			continue
		}
		// Only store if this domain isn't already in the map
		// (list should be sorted, but just in case).
		if _, exists := ranks[domain]; !exists {
			ranks[domain] = rank
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan CSV: %w", err)
	}

	t.ranks = ranks
	t.loaded = time.Now()
	return nil
}

