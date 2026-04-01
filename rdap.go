// File    : rdap.go
// Version : 1.1.0
// Modified: 2026-04-01 17:00 UTC
//
// Changes:
//   v1.1.0 - 2026-04-01 - Per-host throttle backoff on HTTP 429; Retry-After support
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: RDAP (Registration Data Access Protocol) client.
//          Loads the IANA bootstrap registry on first use to map TLDs
//          to their RDAP service base URLs, then queries per-domain.
//          Per-host rate limiting prevents hammering any single registry.
//          Bootstrap JSON is cached locally to avoid redundant downloads.
//          When a registry returns HTTP 429, the host is placed in a
//          configurable backoff window; IsThrottled() lets the validator
//          skip that domain entirely and leave it queued for a later run.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rdapBootstrap mirrors the structure of the IANA RDAP bootstrap JSON.
// Published at: https://data.iana.org/rdap/dns.json
// Format: services is a list of [[tlds...], [base_urls...]] pairs.
type rdapBootstrap struct {
	Publication string       `json:"publication"`
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
	Throttled  bool      // true when the host is in 429 backoff — no data available
	Error      string    // non-empty if the check could not be completed
}

// RDAPClient looks up domain registration status via RDAP.
type RDAPClient struct {
	http            *http.Client
	bootstrap       map[string]string    // TLD → RDAP base URL (lowercase TLD keys)
	bootLoaded      time.Time
	bootPath        string
	bootURL         string
	bootTTL         time.Duration
	minGap          time.Duration        // minimum gap between requests to the same host
	throttleBackoff time.Duration        // how long to back off after a 429

	// All maps below are keyed by RDAP hostname (no port, no scheme).
	lastReq       map[string]time.Time // last successful request timestamp per host
	throttledUntil map[string]time.Time // host → earliest time we may query again

	mu sync.Mutex // protects lastReq, throttledUntil, bootstrap, bootLoaded
}

// NewRDAPClient creates an RDAPClient configured from cfg.
func NewRDAPClient(cfg *Config) *RDAPClient {
	return &RDAPClient{
		http:            &http.Client{Timeout: cfg.RDAP.Timeout},
		bootstrap:       make(map[string]string),
		bootPath:        cfg.RDAP.CachePath,
		bootURL:         cfg.RDAP.BootstrapURL,
		bootTTL:         cfg.RDAP.CacheTTL,
		minGap:          time.Duration(cfg.RDAP.MinGapMs) * time.Millisecond,
		throttleBackoff: cfg.RDAP.ThrottleBackoff,
		lastReq:         make(map[string]time.Time),
		throttledUntil:  make(map[string]time.Time),
	}
}

// IsThrottled reports whether the RDAP host responsible for apex is currently
// in a 429 backoff window. Call this before doing any work for a domain so the
// validator can skip the entire domain instead of firing goroutines that will
// immediately return a throttle error.
//
// Returns false when the bootstrap map is not yet loaded (the domain will be
// attempted normally and the 429 handler will set the throttle for next time).
func (c *RDAPClient) IsThrottled(apex string) bool {
	// findBaseURL acquires/releases mu internally — safe to call here.
	baseURL := c.findBaseURL(apex)
	if baseURL == "" {
		return false
	}
	host := urlHost(baseURL)
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.throttledUntil[host]
	return ok && time.Now().Before(until)
}

// Check performs an RDAP lookup for the apex domain.
// Returns RDAPResult.Active = true when the registry considers the domain active.
// Returns RDAPResult.Throttled = true when the host is in backoff — the caller
// should treat this domain as postponed and not update the store.
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
	host := urlHost(baseURL)

	c.mu.Lock()

	// --- Throttle pre-flight ---
	// A 429 received in a previous call has set throttledUntil for this host.
	// If we're still inside the window, bail immediately without making a request.
	if until, ok := c.throttledUntil[host]; ok && time.Now().Before(until) {
		c.mu.Unlock()
		return RDAPResult{
			Throttled: true,
			Error:     fmt.Sprintf("throttled until %s", until.Format(time.RFC3339)),
		}
	}

	// --- Per-host rate limiting (min gap) ---
	// Enforce a minimum gap between requests to the same RDAP host.
	// Sleep outside the lock so other goroutines aren't blocked.
	wait := c.minGap - time.Since(c.lastReq[host])
	if wait > 0 {
		c.mu.Unlock()
		time.Sleep(wait)
		c.mu.Lock()
	}
	c.lastReq[host] = time.Now()
	c.mu.Unlock()

	queryURL := strings.TrimSuffix(baseURL, "/") + "/domain/" + apex
	resp, err := c.http.Get(queryURL) //nolint:noctx
	if err != nil {
		return RDAPResult{Error: err.Error()}
	}
	defer resp.Body.Close()

	// --- HTTP 429: Too Many Requests ---
	// Set a per-host throttle window. Respect Retry-After if present (in seconds);
	// fall back to the configured throttle_backoff if not.
	if resp.StatusCode == http.StatusTooManyRequests {
		backoff := c.throttleBackoff
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err2 := strconv.Atoi(ra); err2 == nil && secs > 0 {
				if d := time.Duration(secs) * time.Second; d > backoff {
					backoff = d // always honour the longer of the two
				}
			}
		}
		until := time.Now().Add(backoff)
		c.mu.Lock()
		c.throttledUntil[host] = until
		c.mu.Unlock()
		log.Printf("rdap: 429 from %s — backing off until %s", host, until.Format(time.RFC3339))
		return RDAPResult{
			Throttled: true,
			Error:     fmt.Sprintf("HTTP 429 — throttled until %s", until.Format(time.RFC3339)),
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		// 404 = domain not registered with this registry.
		return RDAPResult{Active: false, StatusText: "not_registered"}
	}
	if resp.StatusCode != http.StatusOK {
		return RDAPResult{Error: fmt.Sprintf("HTTP %d from %s", resp.StatusCode, queryURL)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64 KB cap
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

	// Try compound TLD first (e.g. "co.uk"), then simple TLD (e.g. "uk").
	if len(parts) >= 2 {
		compound := strings.Join(parts[len(parts)-2:], ".")
		if u, ok := c.bootstrap[compound]; ok {
			return u
		}
	}
	return c.bootstrap[parts[len(parts)-1]]
}

// ensureBootstrap loads (or refreshes) the TLD→URL map from the IANA bootstrap
// JSON. It tries the local disk cache first to avoid a network round-trip on
// every startup; the cache is refreshed when it exceeds bootTTL.
func (c *RDAPClient) ensureBootstrap() error {
	c.mu.Lock()
	loaded := c.bootLoaded
	c.mu.Unlock()

	if len(c.bootstrap) > 0 && time.Since(loaded) < c.bootTTL {
		return nil
	}

	// Try disk cache.
	if data, err := os.ReadFile(c.bootPath); err == nil {
		if err2 := c.parseBootstrap(data); err2 == nil {
			c.mu.Lock()
			c.bootLoaded = time.Now()
			c.mu.Unlock()
			return nil
		}
	}

	// Download from IANA.
	resp, err := c.http.Get(c.bootURL)
	if err != nil {
		return fmt.Errorf("download bootstrap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return fmt.Errorf("read bootstrap: %w", err)
	}
	// Best-effort cache write; ignore errors (we already have the data in memory).
	_ = os.WriteFile(c.bootPath, data, 0o644)

	if err := c.parseBootstrap(data); err != nil {
		return fmt.Errorf("parse bootstrap: %w", err)
	}
	c.mu.Lock()
	c.bootLoaded = time.Now()
	c.mu.Unlock()
	return nil
}

// parseBootstrap deserialises the IANA bootstrap JSON and populates the
// TLD→baseURL map. Called with the mu already released.
func (c *RDAPClient) parseBootstrap(data []byte) error {
	var bs rdapBootstrap
	if err := json.Unmarshal(data, &bs); err != nil {
		return err
	}
	m := make(map[string]string, len(bs.Services)*4)
	for _, svc := range bs.Services {
		if len(svc) < 2 || len(svc[0]) == 0 || len(svc[1]) == 0 {
			continue
		}
		baseURL := svc[1][0]
		for _, tld := range svc[0] {
			m[strings.ToLower(tld)] = baseURL
		}
	}
	c.mu.Lock()
	c.bootstrap = m
	c.mu.Unlock()
	return nil
}

// urlHost extracts just the hostname from a raw URL string.
// e.g. "https://rdap.verisign.com/com/v1/" → "rdap.verisign.com"
func urlHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		// Fallback: strip scheme and path manually.
		s := rawURL
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		if i := strings.Index(s, "/"); i >= 0 {
			s = s[:i]
		}
		return s
	}
	return u.Hostname() // strips port if present
}

