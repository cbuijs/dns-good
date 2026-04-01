// File    : rootzone.go
// Version : 1.1.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.1.0 - 2026-04-01 - Standardised file header
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Downloads, caches, and parses the IANA root zone file.

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

type RootZone struct {
	tldNS  map[string][]string
	tldSet map[string]bool
	loaded  time.Time
	path    string
	url     string
	ttl     time.Duration
	enabled bool
	mu sync.RWMutex
}

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

func (rz *RootZone) Ensure() error {
	if !rz.enabled { return nil }

	rz.mu.RLock()
	fresh := len(rz.tldSet) > 0 && time.Since(rz.loaded) < rz.ttl
	rz.mu.RUnlock()
	if fresh { return nil }

	if data, err := os.ReadFile(rz.path); err == nil {
		if parseErr := rz.parse(data); parseErr == nil {
			log.Printf("rootzone: loaded %d TLDs from cache", rz.count())
			return nil
		}
	}

	data, err := rz.download()
	if err != nil { return err }
	
	_ = os.WriteFile(rz.path, data, 0o644)
	if err := rz.parse(data); err != nil { return fmt.Errorf("rootzone: parse: %w", err) }
	
	log.Printf("rootzone: downloaded and parsed %d TLDs", rz.count())
	return nil
}

func (rz *RootZone) KnownTLD(tld string) bool {
	if !rz.enabled { return true }
	tld = strings.ToLower(tld)
	rz.mu.RLock()
	known := len(rz.tldSet) == 0 || rz.tldSet[tld]
	rz.mu.RUnlock()
	return known
}

func (rz *RootZone) NSForTLD(tld string) ([]string, bool) {
	if !rz.enabled { return nil, false }
	tld = strings.ToLower(tld)
	rz.mu.RLock()
	ips, ok := rz.tldNS[tld]
	rz.mu.RUnlock()
	if !ok || len(ips) == 0 { return nil, false }
	return ips, true
}

func (rz *RootZone) parse(data []byte) error {
	tldToNS := make(map[string][]string, 1500)
	glue     := make(map[string][]string, 2000)

	zp := dns.NewZoneParser(bytes.NewReader(data), ".", "root.zone")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch v := rr.(type) {
		case *dns.NS:
			owner := strings.ToLower(strings.TrimSuffix(v.Hdr.Name, "."))
			if owner == "" { continue }
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
	if err := zp.Err(); err != nil { return fmt.Errorf("zone parse: %w", err) }

	tldSet := make(map[string]bool, len(tldToNS))
	for tld := range tldToNS { tldSet[tld] = true }

	tldNS := make(map[string][]string, len(tldToNS))
	for tld, nsList := range tldToNS {
		var ips []string
		seen := make(map[string]bool)
		for _, nsHost := range nsList {
			for _, ip := range glue[nsHost] {
				if !seen[ip] {
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
		if len(ips) > 0 { tldNS[tld] = ips }
	}

	rz.mu.Lock()
	rz.tldSet = tldSet
	rz.tldNS  = tldNS
	rz.loaded = time.Now()
	rz.mu.Unlock()
	return nil
}

func (rz *RootZone) download() ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(rz.url)
	if err != nil { return nil, fmt.Errorf("download: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }
	
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil { return nil, fmt.Errorf("read body: %w", err) }
	return data, nil
}

func (rz *RootZone) count() int {
	rz.mu.RLock()
	defer rz.mu.RUnlock()
	return len(rz.tldSet)
}

