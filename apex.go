// File    : apex.go
// Version : 1.1.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.1.0 - 2026-04-01 - Standardised file header
//   v1.0.0 - 2026-04-01 - Initial implementation; replaces the
//                          hardcoded compound-TLD table in store.go
//
// Summary: Apex domain extraction using the Mozilla Public Suffix List
//          via golang.org/x/net/publicsuffix.

package main

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

func extractApex(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return ""
	}

	apex, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		parts := strings.Split(domain, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return domain
	}
	return apex
}

func extractTLD(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if i := strings.LastIndex(domain, "."); i >= 0 {
		return domain[i+1:]
	}
	return domain
}

