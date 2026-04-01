// File    : resolver.go
// Version : 1.1.0
// Modified: 2026-04-01 20:00 UTC
//
// Changes:
//   v1.1.0 - 2026-04-01 - SERVFAIL from one server no longer kills resolution;
//                          other servers in the set are tried first.
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Self-contained iterative DNS resolver. Walks the delegation
//          chain from root → TLD → authoritative NS ourselves, without
//          relying on any upstream recursive resolver for target domains.
//
//          HOW IT WORKS — two completely different modes, don't confuse them:
//
//          ITERATIVE (used for target domains):
//            We do the work. Ask root → get TLD referral → ask TLD → get NS
//            referral → ask authoritative NS → get final answer. Each hop is
//            a separate query from us. RecursionDesired = false on all of them.
//            This is what iterativeResolve() does.
//
//          RECURSIVE (used only for glueless NS hostnames):
//            We delegate the work. Ask 8.8.8.8 "give me the final answer" and
//            it walks the chain for us. RecursionDesired = true. Used only in
//            resolveNStoIPs() when a referral has no glue records — a pragmatic
//            trade-off for NS infrastructure hostnames only.
//
//          The one-server-SERVFAIL bug: query() now treats SERVFAIL as a soft
//          per-server failure and tries the next server in the set. Previously,
//          SERVFAIL from whichever server happened to be picked first would
//          abort the entire resolution, even if the other 3 NS servers were fine.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ianaRootServers is the complete set of IANA root server IPv4 addresses.
// One is picked at random per resolution attempt to spread load across
// the anycast clusters. Updated list: https://www.iana.org/domains/root/servers
var ianaRootServers = []string{
	"198.41.0.4",     // a.root-servers.net
	"170.247.170.2",  // b.root-servers.net
	"192.33.4.12",    // c.root-servers.net
	"199.7.91.13",    // d.root-servers.net
	"192.203.230.10", // e.root-servers.net
	"192.5.5.241",    // f.root-servers.net
	"192.112.36.4",   // g.root-servers.net
	"198.97.190.53",  // h.root-servers.net
	"192.36.148.17",  // i.root-servers.net
	"192.58.128.30",  // j.root-servers.net
	"193.0.14.129",   // k.root-servers.net
	"199.7.83.42",    // l.root-servers.net
	"202.12.27.33",   // m.root-servers.net
}

// publicFallbackResolvers is used ONLY to resolve NS hostnames when no
// glue records are present in a referral (glueless delegation).
// These are NOT used for the target domains themselves.
var publicFallbackResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"9.9.9.9:53", // Quad9
}

// NXDomainError signals that the DNS hierarchy returned NXDOMAIN —
// the domain name does not exist anywhere in the tree.
type NXDomainError struct{ Name string }

func (e *NXDomainError) Error() string { return "NXDOMAIN: " + e.Name }

// ResolveResult holds everything the iterative resolver found.
type ResolveResult struct {
	HasNS   bool
	HasA    bool
	HasAAAA bool
	NS      []string // authoritative NS hostnames for the apex
	A       []net.IP
	AAAA    []net.IP
	Errors  []string // non-fatal issues (e.g. one NS timed out but another answered)
}

// Resolver performs iterative (from-scratch) DNS lookups.
type Resolver struct {
	maxDepth int
	retries  int
	udp      *dns.Client // primary transport
	tcp      *dns.Client // fallback for truncated UDP responses
}

// NewResolver creates a Resolver with the given settings.
func NewResolver(maxDepth, retries int, timeout time.Duration) *Resolver {
	return &Resolver{
		maxDepth: maxDepth,
		retries:  retries,
		udp:      &dns.Client{Net: "udp", Timeout: timeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: timeout * 2},
	}
}

// CheckDomain runs a full iterative check for an apex domain:
//  1. Resolves NS records (confirms zone delegation exists).
//  2. Resolves A and AAAA records from those authoritative servers.
//
// Only the apex domain should be passed here; subdomain A/AAAA checks
// are separate and caller-driven if needed.
func (r *Resolver) CheckDomain(apex string) *ResolveResult {
	res := &ResolveResult{}
	fqdn := dns.Fqdn(strings.ToLower(apex))

	// --- NS / delegation check ---
	nsResp, err := r.iterativeResolve(fqdn, dns.TypeNS)
	if err != nil {
		if !isNXDomain(err) {
			res.Errors = append(res.Errors, "NS: "+err.Error())
		}
		// NXDOMAIN → HasNS stays false, which is the correct result
	} else {
		// NS records can appear in Answer (authoritative response) or Ns
		// (referral / authority section) depending on which server answered.
		for _, rr := range append(nsResp.Answer, nsResp.Ns...) {
			if ns, ok := rr.(*dns.NS); ok {
				res.HasNS = true
				res.NS = append(res.NS, trimFQDN(ns.Ns))
			}
		}
	}

	// --- A record check ---
	aResp, err := r.iterativeResolve(fqdn, dns.TypeA)
	if err != nil && !isNXDomain(err) {
		res.Errors = append(res.Errors, "A: "+err.Error())
	} else if aResp != nil {
		for _, rr := range aResp.Answer {
			if a, ok := rr.(*dns.A); ok {
				res.HasA = true
				res.A = append(res.A, a.A)
			}
		}
	}

	// --- AAAA record check ---
	aaaaResp, err := r.iterativeResolve(fqdn, dns.TypeAAAA)
	if err != nil && !isNXDomain(err) {
		res.Errors = append(res.Errors, "AAAA: "+err.Error())
	} else if aaaaResp != nil {
		for _, rr := range aaaaResp.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				res.HasAAAA = true
				res.AAAA = append(res.AAAA, aaaa.AAAA)
			}
		}
	}

	return res
}

// iterativeResolve walks the DNS hierarchy from a root server, following NS
// referrals at each level, until it gets an authoritative answer for name/qtype.
//
// The walk: root → TLD → authoritative NS → answer. At each step we send a
// non-recursive query (RD=false) and handle whatever comes back:
//
//   Answer section present   → done (or follow CNAME and restart)
//   AA bit set, Answer empty → NODATA (record type absent, domain exists)
//   Authority section NS     → referral; resolve those NS IPs and continue
//   NXDOMAIN rcode           → domain does not exist anywhere in the tree
//   SERVFAIL rcode           → tried all servers, all reported failure
//
// CNAME chains are followed up to 8 hops by restarting the walk for the target.
func (r *Resolver) iterativeResolve(name string, qtype uint16) (*dns.Msg, error) {
	servers := []string{randomRootServer() + ":53"}
	cnameHops := 0

	for depth := 0; depth < r.maxDepth; depth++ {
		resp, err := r.query(name, qtype, servers)
		if err != nil {
			return nil, err
		}

		switch resp.Rcode {
		case dns.RcodeNameError: // NXDOMAIN — domain does not exist
			return nil, &NXDomainError{Name: name}
		case dns.RcodeServerFailure:
			// query() only returns SERVFAIL here if ALL servers in the set
			// returned SERVFAIL — individual server failures are retried
			// against the other servers in the set before reaching this point.
			return nil, fmt.Errorf("SERVFAIL for %s (all authoritative servers failed)", name)
		}

		// Answer section present — we have a result.
		if len(resp.Answer) > 0 {
			// If there's a CNAME and we're not specifically hunting for CNAMEs,
			// restart the walk from root for the canonical target name.
			if qtype != dns.TypeCNAME {
				if target := extractCNAMETarget(resp); target != "" {
					if cnameHops >= 8 {
						return nil, fmt.Errorf("CNAME chain too deep for %s", name)
					}
					name = dns.Fqdn(target)
					servers = []string{randomRootServer() + ":53"}
					cnameHops++
					depth = -1 // post-increment makes this 0 at the top of next iteration
					continue
				}
			}
			return resp, nil
		}

		// AA bit set with empty Answer = NODATA: record type doesn't exist
		// but the domain itself does. Return the response so the caller can
		// inspect the Authority section (often contains SOA or NS).
		if resp.Authoritative {
			return resp, nil
		}

		// Non-authoritative, no Answer → referral. The Authority section has
		// the NS names for the next level; Additional has glue IPs (if any).
		nsNames := extractNSNames(resp)
		if len(nsNames) == 0 {
			return nil, fmt.Errorf("no referral at depth %d for %s", depth, name)
		}
		glue := extractGlue(resp)
		ips := r.resolveNStoIPs(nsNames, glue)
		if len(ips) == 0 {
			return nil, fmt.Errorf("cannot resolve NS IPs at depth %d for %s", depth, name)
		}
		servers = addPort(ips, "53")
	}

	return nil, fmt.Errorf("max delegation depth %d exceeded for %s", r.maxDepth, name)
}

// query sends name/qtype to each server in shuffled order with UDP, falling
// back to TCP on truncation.
//
// SERVFAIL from a single server is a soft failure — we skip to the next server.
// This is the fix for the one-bad-NS-kills-everything bug: in a typical setup
// with 4 authoritative servers, one returning SERVFAIL should not abort the
// entire resolution. Only if ALL servers return SERVFAIL (or time out) do we
// propagate the failure to the caller.
func (r *Resolver) query(name string, qtype uint16, servers []string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false // we follow referrals ourselves; never ask a server to recurse
	m.SetEdns0(1232, false)    // EDNS0 buffer size per RFC 8085 recommendation

	shuffled := make([]string, len(servers))
	copy(shuffled, servers)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	var lastErr error
	var servfailResp *dns.Msg // saved in case every server SERVFAILs

	for _, srv := range shuffled {
		for try := 0; try <= r.retries; try++ {
			resp, _, err := r.udp.Exchange(m, srv)
			if err != nil {
				lastErr = err
				continue // retry same server
			}
			if resp.Truncated {
				// UDP payload too large — retry this server over TCP.
				resp, _, err = r.tcp.Exchange(m, srv)
				if err != nil {
					lastErr = err
					continue // retry same server
				}
			}

			// SERVFAIL from this specific server — don't give up yet.
			// Break the retry loop for this server and try the next one.
			if resp.Rcode == dns.RcodeServerFailure {
				lastErr = fmt.Errorf("SERVFAIL from %s for %s %s",
					srv, name, dns.TypeToString[qtype])
				servfailResp = resp
				break // move to next server in outer loop
			}

			return resp, nil // success (NOERROR, NXDOMAIN, etc.)
		}
	}

	// Every server either timed out or returned SERVFAIL.
	// Return the SERVFAIL response if we have one — the caller can inspect
	// the Rcode directly and emit a useful error. Otherwise return the last
	// transport error.
	if servfailResp != nil {
		return servfailResp, nil
	}
	return nil, fmt.Errorf("all servers failed for %s %s: %w",
		name, dns.TypeToString[qtype], lastErr)
}

// resolveNStoIPs maps NS hostnames to IP address strings.
// Glue records from the referral are used first (no extra query needed).
// For glueless delegations, falls back to public resolvers — see file header.
// Capped at 4 NS servers to keep the number of lookups bounded.
func (r *Resolver) resolveNStoIPs(names []string, glue map[string][]string) []string {
	limit := 4
	if len(names) < limit {
		limit = len(names)
	}

	var ips []string
	seen := make(map[string]bool)

	for _, name := range names[:limit] {
		if addrs, ok := glue[name]; ok {
			// Glue present — use it directly, no extra query needed.
			for _, ip := range addrs {
				if !seen[ip] {
					ips = append(ips, ip)
					seen[ip] = true
				}
			}
			continue
		}

		// No glue (glueless delegation) — ask a public recursive resolver.
		// RD=true here is intentional: we're resolving DNS infrastructure
		// hostnames, not target domains, so delegating to a public resolver
		// is an acceptable trade-off (see file header for reasoning).
		for _, pub := range publicFallbackResolvers {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(name), dns.TypeA)
			m.RecursionDesired = true
			resp, _, err := r.udp.Exchange(m, pub)
			if err != nil || resp == nil {
				continue
			}
			found := false
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					ip := a.A.String()
					if !seen[ip] {
						ips = append(ips, ip)
						seen[ip] = true
						found = true
					}
				}
			}
			if found {
				break
			}
		}
	}
	return ips
}

// --- helpers ---

func randomRootServer() string {
	return ianaRootServers[rand.Intn(len(ianaRootServers))]
}

func isNXDomain(err error) bool {
	_, ok := err.(*NXDomainError)
	return ok
}

func trimFQDN(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func extractNSNames(msg *dns.Msg) []string {
	var ns []string
	for _, rr := range msg.Ns {
		if n, ok := rr.(*dns.NS); ok {
			ns = append(ns, trimFQDN(n.Ns))
		}
	}
	return ns
}

// extractGlue collects A and AAAA records from the Additional section,
// keyed by hostname — these are glue records accompanying an NS referral.
func extractGlue(msg *dns.Msg) map[string][]string {
	glue := make(map[string][]string)
	for _, rr := range msg.Extra {
		switch a := rr.(type) {
		case *dns.A:
			host := trimFQDN(a.Hdr.Name)
			glue[host] = append(glue[host], a.A.String())
		case *dns.AAAA:
			host := trimFQDN(a.Hdr.Name)
			glue[host] = append(glue[host], a.AAAA.String())
		}
	}
	return glue
}

// extractCNAMETarget returns the first CNAME target in the Answer section,
// or empty string if none is present.
func extractCNAMETarget(msg *dns.Msg) string {
	for _, rr := range msg.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			return trimFQDN(c.Target)
		}
	}
	return ""
}

// addPort appends ":port" to each IP string, wrapping IPv6 addresses in brackets.
func addPort(ips []string, port string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() == nil {
			out = append(out, "["+ip+"]:"+port) // IPv6
		} else {
			out = append(out, ip+":"+port)
		}
	}
	return out
}

