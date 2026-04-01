// File    : rootzone.go
// Version : 1.0.0
// Modified: 2026-04-01 19:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Downloads, caches, and parses the IANA root zone file.
//          Provides two things to the rest of the application:
//
//            KnownTLD(tld)  — fast boolean pre-check before any network
//                             work; unknown TLD → immediate NXDOMAIN
//
//            NSForTLD(tld)  — IP:port pairs for the TLD's authoritative
//                             nameservers, assembled from in-zone glue
//                             records. When available these let the
//                             resolver skip the root server hop entirely.
//
//          The root zone is ~2 MB and changes slowly (new TLD delegations,
//          NS/glue updates). A 24h refresh TTL is conservative and safe.
//          The file is parsed using the miekg/dns zone parser — same dep
//          already used by the resolver.
//
//          When disabled (rootzone.enabled: false), KnownTLD always returns
//          true and NSForTLD always returns nil — the resolver falls back to
//          its normal root server behaviour, so nothing breaks.

package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RootZone holds the parsed IANA root zone in memory.
type RootZone struct {
	// tldNS maps lowercase TLD label → []"IP:53" strings ready for the resolver.
	// Only populated for TLDs whose NS hostnames have in-zone glue records.
	// TLDs without glue (some ccTLDs use out-of-zone NS) are in tldSet but
	// not in tldNS — the resolver falls back to root queries for those.
	tldNS  map[string][]string
	tldSet map[string]bool // every TLD in the root zone, glue or not

	loaded  time.Time
	path    string
	url     string
	ttl     time.Duration
	enabled bool

	mu sync.RWMutex
}

// NewRootZone creates a RootZone from config. Call Ensure() before first use.
func NewRootZone(cfg *Config) *RootZone {
	return &RootZone{
		tldNS:   make(map[string][]string),
		tldSet:  make(map[string]bool),
		path:    cfg.RootZone.CachePath,
		url:     cfg.RootZone.URL,
		ttl:     cfg.RootZone.RefreshTTL,
		enabled: cfg.RootZone.Enabled,
	}
}

// Ensure loads the root zone into memory, downloading or refreshing as needed.
// Safe to call multiple times — does nothing if the data is still fresh.
// Called once at startup from main; not called per-domain.
func (rz *RootZone) Ensure() error {
	if !rz.enabled {
		return nil
	}

	rz.mu.RLock()
	fresh := len(rz.tldSet) > 0 && time.Since(rz.loaded) < rz.ttl
	rz.mu.RUnlock()
	if fresh {
		return nil
	}

	// Try disk cache first — avoids a download on every restart.
	if data, err := os.ReadFile(rz.path); err == nil {
		if parseErr := rz.parse(data); parseErr == nil {
			log.Printf("rootzone: loaded %d TLDs from cache (%s)", rz.count(), rz.path)
			return nil
		}
		// Cache corrupt or unparse-able — fall through to download.
		log.Printf("rootzone: cache parse failed, downloading fresh copy")
	}

	data, err := rz.download()
	if err != nil {
		return err
	}
	// Best-effort write; ignore errors — we have the data in memory regardless.
	if writeErr := os.WriteFile(rz.path, data, 0o644); writeErr != nil {
		log.Printf("rootzone: could not write cache %s: %v", rz.path, writeErr)
	}
	if err := rz.parse(data); err != nil {
		return fmt.Errorf("rootzone: parse: %w", err)
	}
	log.Printf("rootzone: downloaded and parsed %d TLDs (%d with glue NS IPs)",
		rz.count(), rz.countWithNS())
	return nil
}

// KnownTLD reports whether tld (single label, e.g. "com", "uk") exists in the
// root zone. Returns true unconditionally when the root zone is disabled or not
// yet loaded, so the resolver never rejects a domain just because we haven't
// fetched the zone yet.
func (rz *RootZone) KnownTLD(tld string) bool {
	if !rz.enabled {
		return true
	}
	tld = strings.ToLower(tld)
	rz.mu.RLock()
	known := len(rz.tldSet) == 0 || rz.tldSet[tld] // also true when map is empty (not loaded)
	rz.mu.RUnlock()
	return known
}

// NSForTLD returns ready-to-dial "IP:53" strings for the authoritative
// nameservers of tld, taken from root zone glue records. Returns nil, false
// when the root zone is disabled, the TLD has no in-zone glue, or the zone
// is not yet loaded — in all those cases the resolver falls back to querying
// a root server directly.
func (rz *RootZone) NSForTLD(tld string) ([]string, bool) {
	if !rz.enabled {
		return nil, false
	}
	tld = strings.ToLower(tld)
	rz.mu.RLock()
	ips, ok := rz.tldNS[tld]
	rz.mu.RUnlock()
	if !ok || len(ips) == 0 {
		return nil, false
	}
	return ips, true
}

// --- internal ---

// parse ingests raw root zone text using the miekg/dns zone parser.
// Two passes through the same byte slice:
//   1. Collect NS records: TLD label → []NS hostname
//   2. Collect A/AAAA records: NS hostname → []IP  (in-zone glue)
//
// Then cross-reference to produce the final tldNS map (TLD → []IP:53).
func (rz *RootZone) parse(data []byte) error {
	// Pass 1 — NS records.
	tldToNS := make(map[string][]string, 1500) // ~1400 TLDs in current root zone
	glue     := make(map[string][]string, 2000) // glue IPs per NS hostname

	zp := dns.NewZoneParser(bytes.NewReader(data), ".", "root.zone")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch v := rr.(type) {
		case *dns.NS:
			owner := strings.ToLower(strings.TrimSuffix(v.Hdr.Name, "."))
			if owner == "" {
				continue // root's own NS records — skip
			}
			ns := strings.ToLower(strings.TrimSuffix(v.Ns, "."))
			tldToNS[owner] = append(tldToNS[owner], ns)

		case *dns.A:
			host := strings.ToLower(strings.TrimSuffix(v.Hdr.Name, "."))
			glue[host] = append(glue[host], v.A.String())

		case *dns.AAAA:
			host := strings.ToLower(strings.TrimSuffix(v.Hdr.Name, "."))
			glue[host] = append(glue[host], v.AAAA.String())
		}
	}
	if err := zp.Err(); err != nil {
		return fmt.Errorf("zone parse: %w", err)
	}

	// Build tldSet from all observed NS owners.
	tldSet := make(map[string]bool, len(tldToNS))
	for tld := range tldToNS {
		tldSet[tld] = true
	}

	// Cross-reference: for each TLD, collect IPs of its NS hosts that have
	// in-zone glue. At least one IP is enough — the referral loop in the
	// resolver will chase the full NS list from there.
	tldNS := make(map[string][]string, len(tldToNS))
	for tld, nsList := range tldToNS {
		var ips []string
		seen := make(map[string]bool)
		for _, nsHost := range nsList {
			for _, ip := range glue[nsHost] {
				if !seen[ip] {
					// Wrap IPv6 in brackets so the string is dial-ready.
					parsed := net.ParseIP(ip)
					if parsed != nil && parsed.To4() == nil {
						ips = append(ips, "["+ip+"]:53")
					} else {
						ips = append(ips, ip+":53")
					}
					seen[ip] = true
				}
			}
		}
		if len(ips) > 0 {
			tldNS[tld] = ips
		}
	}

	rz.mu.Lock()
	rz.tldSet = tldSet
	rz.tldNS  = tldNS
	rz.loaded = time.Now()
	rz.mu.Unlock()
	return nil
}

// download fetches the root zone from the configured URL.
func (rz *RootZone) download() ([]byte, error) {
	log.Printf("rootzone: downloading from %s", rz.url)
	client := &http.Client{Timeout: 60 * time.Second} // zone file can be slow on first fetch
	resp, err := client.Get(rz.url)
	if err != nil {
		return nil, fmt.Errorf("rootzone: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rootzone: download: HTTP %d", resp.StatusCode)
	}
	// Root zone is currently ~2 MB; 8 MB cap is very generous headroom.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("rootzone: read body: %w", err)
	}
	return data, nil
}

func (rz *RootZone) count() int {
	rz.mu.RLock()
	defer rz.mu.RUnlock()
	return len(rz.tldSet)
}

func (rz *RootZone) countWithNS() int {
	rz.mu.RLock()
	defer rz.mu.RUnlock()
	return len(rz.tldNS)
}

