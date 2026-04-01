// File    : topn.go
// Version : 1.1.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.1.0 - 2026-04-01 - Standardised file header
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: TOP-N domain list manager. Provides fast apex-domain lookups.

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

type TopN struct {
	ranks      map[string]int
	provider   string
	url        string
	cachePath  string
	refreshTTL time.Duration
	size       int
	loaded     time.Time
	mu         sync.RWMutex
}

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

func (t *TopN) Rank(apex string) int {
	if err := t.ensureLoaded(); err != nil { return 0 }
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ranks[strings.ToLower(apex)]
}

func (t *TopN) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.ranks)
}

func (t *TopN) ensureLoaded() error {
	t.mu.RLock()
	fresh := len(t.ranks) > 0 && time.Since(t.loaded) < t.refreshTTL
	t.mu.RUnlock()
	if fresh { return nil }

	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.ranks) > 0 && time.Since(t.loaded) < t.refreshTTL { return nil }

	if info, err := os.Stat(t.cachePath); err == nil {
		if time.Since(info.ModTime()) < t.refreshTTL {
			return t.loadFromCSVFile(t.cachePath)
		}
	}

	data, err := t.download()
	if err != nil {
		if _, serr := os.Stat(t.cachePath); serr == nil {
			_ = t.loadFromCSVFile(t.cachePath)
			return nil
		}
		return fmt.Errorf("download TOP-N list (%s): %w", t.provider, err)
	}

	return t.extractAndCache(data)
}

func (t *TopN) download() ([]byte, error) {
	resp, err := http.Get(t.url)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, t.url) }
	return io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
}

func (t *TopN) extractAndCache(data []byte) error {
	csvData := data
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for _, f := range zr.File {
			if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
				rc, err := f.Open()
				if err != nil { return fmt.Errorf("open zip entry %s: %w", f.Name, err) }
				csvData, err = io.ReadAll(rc)
				rc.Close()
				if err != nil { return fmt.Errorf("read zip entry %s: %w", f.Name, err) }
				break
			}
		}
	}
	if len(csvData) == 0 { return fmt.Errorf("no CSV data found") }
	if err := os.WriteFile(t.cachePath, csvData, 0o644); err != nil { return fmt.Errorf("write cache: %w", err) }
	return t.parseCSV(csvData)
}

func (t *TopN) loadFromCSVFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil { return fmt.Errorf("read cache: %w", err) }
	return t.parseCSV(data)
}

func (t *TopN) parseCSV(data []byte) error {
	ranks := make(map[string]int, t.size)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	count := 0

	for scanner.Scan() {
		if count >= t.size { break }
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 { continue }
		rank, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || rank <= 0 { continue }
		domain := strings.ToLower(strings.TrimSpace(parts[1]))
		if domain == "" { continue }
		if _, exists := ranks[domain]; !exists {
			ranks[domain] = rank
			count++
		}
	}

	if err := scanner.Err(); err != nil { return fmt.Errorf("scan CSV: %w", err) }
	t.ranks = ranks
	t.loaded = time.Now()
	return nil
}

