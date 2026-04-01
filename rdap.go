// File    : rdap.go
// Version : 1.3.0
// Modified: 2026-04-01 16:54 UTC
//
// Changes:
//   v1.3.0 - 2026-04-01 - Backoff on all non-2xx HTTP responses (excluding 404)
//   v1.2.0 - 2026-04-01 - Standardised file header
//   v1.1.0 - 2026-04-01 - Per-host throttle backoff on HTTP 429; Retry-After support
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: RDAP (Registration Data Access Protocol) client. Handles dynamic lookup
//          and robust HTTP throttle fallback/retrying on rate limits and server errors.

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

type rdapBootstrap struct {
	Publication string       `json:"publication"`
	Services    [][][]string `json:"services"`
}

type rdapDomainResponse struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

type RDAPResult struct {
	Active     bool
	StatusText string
	Expiry     time.Time
	Throttled  bool
	Error      string
}

type RDAPClient struct {
	http            *http.Client
	bootstrap       map[string]string
	bootLoaded      time.Time
	bootPath        string
	bootURL         string
	bootTTL         time.Duration
	minGap          time.Duration
	throttleBackoff time.Duration
	lastReq         map[string]time.Time
	throttledUntil  map[string]time.Time
	mu              sync.Mutex
}

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

func (c *RDAPClient) IsThrottled(apex string) bool {
	baseURL := c.findBaseURL(apex)
	if baseURL == "" { return false }
	host := urlHost(baseURL)
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.throttledUntil[host]
	return ok && time.Now().Before(until)
}

func (c *RDAPClient) Check(apex string) RDAPResult {
	if err := c.ensureBootstrap(); err != nil {
		return RDAPResult{Error: "bootstrap: " + err.Error()}
	}

	baseURL := c.findBaseURL(apex)
	if baseURL == "" {
		return RDAPResult{Error: fmt.Sprintf("no RDAP service known for %q", apex)}
	}
	host := urlHost(baseURL)

	c.mu.Lock()
	if until, ok := c.throttledUntil[host]; ok && time.Now().Before(until) {
		c.mu.Unlock()
		return RDAPResult{ Throttled: true, Error: fmt.Sprintf("throttled until %s", until.Format(time.RFC3339)) }
	}

	wait := c.minGap - time.Since(c.lastReq[host])
	if wait > 0 {
		c.mu.Unlock()
		time.Sleep(wait)
		c.mu.Lock()
	}
	c.lastReq[host] = time.Now()
	c.mu.Unlock()

	queryURL := strings.TrimSuffix(baseURL, "/") + "/domain/" + apex
	resp, err := c.http.Get(queryURL)
	if err != nil { return RDAPResult{Error: err.Error()} }
	defer resp.Body.Close()

	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	is404 := resp.StatusCode == http.StatusNotFound

	// Throttle on any non-2xx response, but explicitly exclude 404 (Not Found)
	// because 404 is the standard RDAP response for an unregistered domain.
	if !is2xx && !is404 {
		backoff := c.throttleBackoff
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err2 := strconv.Atoi(ra); err2 == nil && secs > 0 {
				if d := time.Duration(secs) * time.Second; d > backoff { backoff = d }
			}
		}
		until := time.Now().Add(backoff)
		c.mu.Lock()
		c.throttledUntil[host] = until
		c.mu.Unlock()
		log.Printf("rdap: HTTP %d from %s — backing off until %s", resp.StatusCode, host, until.Format(time.RFC3339))
		return RDAPResult{ Throttled: true, Error: fmt.Sprintf("HTTP %d — throttled until %s", resp.StatusCode, until.Format(time.RFC3339)) }
	}

	if is404 { return RDAPResult{Active: false, StatusText: "not_registered"} }

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil { return RDAPResult{Error: "read body: " + err.Error()} }

	var dr rdapDomainResponse
	if err := json.Unmarshal(body, &dr); err != nil { return RDAPResult{Error: "parse JSON: " + err.Error()} }

	result := RDAPResult{StatusText: strings.Join(dr.Status, ",")}
	for _, s := range dr.Status {
		sl := strings.ToLower(s)
		if sl == "active" || strings.Contains(sl, "prohibit") {
			result.Active = true
			break
		}
	}

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

func (c *RDAPClient) findBaseURL(apex string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(apex, ".")), ".")
	if len(parts) == 0 { return "" }

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(parts) >= 2 {
		compound := strings.Join(parts[len(parts)-2:], ".")
		if u, ok := c.bootstrap[compound]; ok { return u }
	}
	return c.bootstrap[parts[len(parts)-1]]
}

func (c *RDAPClient) ensureBootstrap() error {
	c.mu.Lock()
	loaded := c.bootLoaded
	c.mu.Unlock()

	if len(c.bootstrap) > 0 && time.Since(loaded) < c.bootTTL { return nil }

	if data, err := os.ReadFile(c.bootPath); err == nil {
		if err2 := c.parseBootstrap(data); err2 == nil {
			c.mu.Lock()
			c.bootLoaded = time.Now()
			c.mu.Unlock()
			return nil
		}
	}

	resp, err := c.http.Get(c.bootURL)
	if err != nil { return fmt.Errorf("download bootstrap: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return fmt.Errorf("bootstrap HTTP %d", resp.StatusCode) }
	
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil { return fmt.Errorf("read bootstrap: %w", err) }
	
	_ = os.WriteFile(c.bootPath, data, 0o644)
	if err := c.parseBootstrap(data); err != nil { return fmt.Errorf("parse bootstrap: %w", err) }
	
	c.mu.Lock()
	c.bootLoaded = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *RDAPClient) parseBootstrap(data []byte) error {
	var bs rdapBootstrap
	if err := json.Unmarshal(data, &bs); err != nil { return err }
	m := make(map[string]string, len(bs.Services)*4)
	for _, svc := range bs.Services {
		if len(svc) < 2 || len(svc[0]) == 0 || len(svc[1]) == 0 { continue }
		baseURL := svc[1][0]
		for _, tld := range svc[0] { m[strings.ToLower(tld)] = baseURL }
	}
	c.mu.Lock()
	c.bootstrap = m
	c.mu.Unlock()
	return nil
}

func urlHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		s := rawURL
		if i := strings.Index(s, "://"); i >= 0 { s = s[i+3:] }
		if i := strings.Index(s, "/"); i >= 0 { s = s[:i] }
		return s
	}
	return u.Hostname()
}

