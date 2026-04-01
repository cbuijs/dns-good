// File    : rdap.go
// Version : 1.0.0
// Modified: 2026-04-01 12:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: RDAP (Registration Data Access Protocol) client.
//          Loads the IANA bootstrap registry on first use to map TLDs
//          to their RDAP service base URLs, then queries per-domain.
//          Per-host rate limiting prevents hammering any single registry.
//          Bootstrap JSON is cached locally to avoid redundant downloads.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// rdapBootstrap mirrors the structure of the IANA RDAP bootstrap JSON.
// Published at: https://data.iana.org/rdap/dns.json
// Format: services is a list of [[tlds...], [base_urls...]] pairs.
type rdapBootstrap struct {
	Publication string      `json:"publication"`
	Services    [][][]string `json:"services"`
}

// rdapDomainResponse is the relevant subset of an RDAP domain lookup response.
// Full spec: RFC 9083.
type rdapDomainResponse struct {
	LDHName string   `json:"ldhName"` // ASCII domain name
	Status  []string `json:"status"`  // e.g. ["active", "client delete prohibited"]
	Events  []struct {
		Action string `json:"eventAction"` // e.g. "registration", "expiration"
		Date   string `json:"eventDate"`   // RFC 3339 timestamp
	} `json:"events"`
}

// RDAPResult is returned to the validator for each domain checked.
type RDAPResult struct {
	Active     bool
	StatusText string    // raw status value(s) joined with commas
	Expiry     time.Time // from "expiration" event; zero if not present
	Error      string    // non-empty if the check could not be completed
}

// RDAPClient looks up domain registration status via RDAP.
type RDAPClient struct {
	http       *http.Client
	bootstrap  map[string]string // TLD → RDAP base URL (lowercase TLD keys)
	bootLoaded time.Time
	bootPath   string
	bootURL    string
	bootTTL    time.Duration
	minGap     time.Duration        // minimum gap between requests to the same host
	lastReq    map[string]time.Time // last request timestamp per RDAP host
	mu         sync.Mutex
}

// NewRDAPClient creates an RDAPClient configured from cfg.
func NewRDAPClient(cfg *Config) *RDAPClient {
	return &RDAPClient{
		http:      &http.Client{Timeout: cfg.RDAP.Timeout},
		bootstrap: make(map[string]string),
		bootPath:  cfg.RDAP.CachePath,
		bootURL:   cfg.RDAP.BootstrapURL,
		bootTTL:   cfg.RDAP.CacheTTL,
		minGap:    time.Duration(cfg.RDAP.MinGapMs) * time.Millisecond,
		lastReq:   make(map[string]time.Time),
	}
}

// Check performs an RDAP lookup for the apex domain.
// Returns RDAPResult.Active = true when the registry considers the domain active.
func (c *RDAPClient) Check(apex string) RDAPResult {
	if err := c.ensureBootstrap(); err != nil {
		return RDAPResult{Error: "bootstrap: " + err.Error()}
	}

	// Try simple TLD first (e.g. "uk" for "example.co.uk"), then compound
	// (e.g. "co.uk"). The IANA bootstrap uses the effective TLD as key.
	baseURL := c.findBaseURL(apex)
	if baseURL == "" {
		return RDAPResult{Error: fmt.Sprintf("no RDAP service known for %q", apex)}
	}

	// Per-host rate limiting: enforce a minimum gap between requests to
	// the same RDAP host. We hold the lock just long enough to check and
	// update the timestamp, sleeping outside the lock.
	host := urlHost(baseURL)
	c.mu.Lock()
	wait := c.minGap - time.Since(c.lastReq[host])
	if wait > 0 {
		c.mu.Unlock()
		time.Sleep(wait)
		c.mu.Lock()
	}
	c.lastReq[host] = time.Now()
	c.mu.Unlock()

	url := strings.TrimSuffix(baseURL, "/") + "/domain/" + apex
	resp, err := c.http.Get(url) //nolint:noctx
	if err != nil {
		return RDAPResult{Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// 404 = domain not registered with this registry
		return RDAPResult{Active: false, StatusText: "not_registered"}
	}
	if resp.StatusCode != http.StatusOK {
		return RDAPResult{Error: fmt.Sprintf("HTTP %d from %s", resp.StatusCode, url)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB cap
	if err != nil {
		return RDAPResult{Error: "read body: " + err.Error()}
	}

	var dr rdapDomainResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return RDAPResult{Error: "parse JSON: " + err.Error()}
	}

	result := RDAPResult{StatusText: strings.Join(dr.Status, ",")}

	// "active" in the status array is the canonical indicator.
	// Some registries list only prohibitions (e.g. "client delete prohibited")
	// without explicitly stating "active" — we treat those as active too since
	// prohibitions only apply to registered, live domains.
	for _, s := range dr.Status {
		sl := strings.ToLower(s)
		if sl == "active" || strings.Contains(sl, "prohibit") {
			result.Active = true
			break
		}
	}

	// Parse expiry from events; override Active if the domain has expired.
	for _, ev := range dr.Events {
		if strings.EqualFold(ev.Action, "expiration") {
			t, err := time.Parse(time.RFC3339, ev.Date)
			if err == nil {
				result.Expiry = t
				if t.Before(time.Now()) {
					result.Active = false
					result.StatusText += ",expired"
				}
			}
		}
	}

	return result
}

// findBaseURL returns the RDAP base URL for the given apex domain,
// trying both the simple TLD (last label) and any compound TLD.
func (c *RDAPClient) findBaseURL(apex string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(apex, ".")), ".")
	if len(parts) == 0 {
		return ""
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Try compound TLD first (e.g. "co.uk") for ccSLDs
	if len(parts) >= 3 {
		compound := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if url, ok := c.bootstrap[compound]; ok {
			return url
		}
	}
	// Fall back to simple TLD (e.g. "uk", "com")
	return c.bootstrap[parts[len(parts)-1]]
}

// ensureBootstrap loads the IANA RDAP bootstrap data, preferring a fresh
// local cache file and falling back to downloading from bootstrapURL.
func (c *RDAPClient) ensureBootstrap() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.bootstrap) > 0 && time.Since(c.bootLoaded) < c.bootTTL {
		return nil // in-memory copy is still fresh
	}

	// Check whether the local cache file is fresh enough.
	if info, err := os.Stat(c.bootPath); err == nil {
		if time.Since(info.ModTime()) < c.bootTTL {
			return c.loadBootstrapFile(c.bootPath)
		}
	}

	// Download a fresh copy.
	resp, err := c.http.Get(c.bootURL) //nolint:noctx
	if err != nil {
		// Download failed — use stale cache if available rather than failing hard.
		if _, serr := os.Stat(c.bootPath); serr == nil {
			return c.loadBootstrapFile(c.bootPath)
		}
		return fmt.Errorf("download %s: %w", c.bootURL, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB cap
	if err != nil {
		return fmt.Errorf("read bootstrap: %w", err)
	}
	if err := os.WriteFile(c.bootPath, data, 0o644); err != nil {
		return fmt.Errorf("cache bootstrap to %s: %w", c.bootPath, err)
	}
	return c.parseBootstrap(data)
}

func (c *RDAPClient) loadBootstrapFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return c.parseBootstrap(data)
}

// parseBootstrap builds the TLD → URL map from the IANA bootstrap JSON.
// Acquires no locks — callers must hold c.mu.
func (c *RDAPClient) parseBootstrap(data []byte) error {
	var b rdapBootstrap
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("parse bootstrap JSON: %w", err)
	}
	m := make(map[string]string, 512)
	for _, svc := range b.Services {
		if len(svc) < 2 || len(svc[1]) == 0 {
			continue
		}
		baseURL := svc[1][0] // first listed URL is the primary service endpoint
		for _, tld := range svc[0] {
			m[strings.ToLower(tld)] = baseURL
		}
	}
	c.bootstrap = m
	c.bootLoaded = time.Now()
	return nil
}

// urlHost extracts just the host part from a URL string (for rate limit keying).
func urlHost(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		return s[:idx]
	}
	return s
}

