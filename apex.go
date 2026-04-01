// File    : apex.go
// Version : 1.0.0
// Modified: 2026-04-01 19:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation; replaces the
//                          hardcoded compound-TLD table in store.go
//
// Summary: Apex domain extraction using the Mozilla Public Suffix List
//          via golang.org/x/net/publicsuffix.
//
//          The PSL covers all ~9000 known public suffixes — gTLDs, ccTLDs,
//          and second-level registries like co.uk, com.au, co.jp, etc.
//          This replaces the old hand-rolled ~20-entry table in store.go,
//          which silently produced wrong apexes for most eTLD domains
//          (e.g. "example.co.uk" → "co.uk" instead of "example.co.uk").
//
//          Correct apex extraction matters for:
//            - RDAP lookup (queries the apex, not a subdomain)
//            - TOP-N rank lookup (Tranco list uses registered domains)
//            - Store deduplication (same apex across many submitted subdomains)
//
//          NOTE: Delete the extractApex function from store.go — this file
//          is the canonical single definition going forward.
//
//          The PSL is embedded in the x/net module at compile time. Refresh
//          with "go get -u golang.org/x/net" to pick up new TLD entries.
//          For most operational purposes the embedded list is plenty current.

package main

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// extractApex returns the registered apex domain (eTLD+1) for any input.
// Handles all public suffixes correctly: single-label TLDs (com, net, org),
// two-label eTLDs (co.uk, com.au, co.jp), and ICANN-delegated new gTLDs.
//
// Examples:
//   "example.com"        → "example.com"
//   "sub.example.com"    → "example.com"
//   "example.co.uk"      → "example.co.uk"
//   "sub.example.co.uk"  → "example.co.uk"
//   "example.com.au"     → "example.com.au"
//
// The function is safe to call with or without a trailing dot (FQDN style).
// It always returns a lowercase, dot-free result.
func extractApex(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return ""
	}

	apex, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// EffectiveTLDPlusOne fails when:
		//   - the input IS a public suffix itself (e.g. someone submitted "co.uk")
		//   - the TLD is unknown to the embedded PSL
		// In both cases, fall back to the last two labels — best effort.
		parts := strings.Split(domain, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return domain
	}
	return apex
}

// extractTLD returns the rightmost single label of a domain name.
// Used by the resolver to look up TLD nameservers in the root zone cache.
// This is NOT the same as the public suffix — it's always a single label.
//
// Examples:
//   "example.com"    → "com"
//   "example.co.uk"  → "uk"
//   "example.com."   → "com"  (FQDN style, trailing dot stripped)
func extractTLD(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if i := strings.LastIndex(domain, "."); i >= 0 {
		return domain[i+1:]
	}
	return domain // single-label — is itself a TLD
}

