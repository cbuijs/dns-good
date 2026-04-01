// File    : resolver.go
// Version : 1.3.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.3.0 - 2026-04-01 - Add SOA check to fix "no referral", add CNAME checking, TCP fallback for glueless NS
//   v1.2.0 - 2026-04-01 - Root zone integration: skip root hop for known TLDs;
//                          fast NXDOMAIN on unknown TLDs; extractTLD moved to apex.go
//   v1.1.0 - 2026-04-01 - SERVFAIL from one server no longer kills resolution;
//                          other servers in the set are tried first
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Self-contained iterative DNS resolver. Walks the delegation
//          chain from root → TLD → authoritative NS ourselves, without
//          relying on any upstream recursive resolver for target domains.

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
var publicFallbackResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"9.9.9.9:53", // Quad9
}

// NXDomainError signals that the DNS hierarchy returned NXDOMAIN.
type NXDomainError struct{ Name string }

func (e *NXDomainError) Error() string { return "NXDOMAIN: " + e.Name }

// ResolveResult holds everything the iterative resolver found.
type ResolveResult struct {
	HasNS       bool
	HasA        bool
	HasAAAA     bool
	HasCNAME    bool
	CNAMETarget string
	NS          []string // authoritative NS hostnames for the apex
	A           []net.IP
	AAAA        []net.IP
	Errors      []string // non-fatal issues
}

// Resolver performs iterative (from-scratch) DNS lookups.
type Resolver struct {
	maxDepth int
	retries  int
	udp      *dns.Client // primary transport
	tcp      *dns.Client // fallback for truncated UDP responses
	rootZone *RootZone   // optional; nil disables root zone optimisation
}

// NewResolver creates a Resolver with the given settings.
func NewResolver(maxDepth, retries int, timeout time.Duration, rz *RootZone) *Resolver {
	return &Resolver{
		maxDepth: maxDepth,
		retries:  retries,
		udp:      &dns.Client{Net: "udp", Timeout: timeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: timeout * 2},
		rootZone: rz,
	}
}

// CheckDomain runs a full iterative check for an apex domain.
func (r *Resolver) CheckDomain(apex string) *ResolveResult {
	res := &ResolveResult{}
	fqdn := dns.Fqdn(strings.ToLower(apex))

	// --- NS / delegation check ---
	nsResp, err := r.iterativeResolve(fqdn, dns.TypeNS)
	if err != nil {
		if !isNXDomain(err) {
			res.Errors = append(res.Errors, "NS: "+err.Error())
		}
	} else {
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

	// --- CNAME check (ensures domains correctly register as ACTIVE even if targets fail) ---
	cnameResp, err := r.iterativeResolve(fqdn, dns.TypeCNAME)
	if err != nil && !isNXDomain(err) {
		res.Errors = append(res.Errors, "CNAME: "+err.Error())
	} else if cnameResp != nil {
		for _, rr := range cnameResp.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				res.HasCNAME = true
				res.CNAMETarget = trimFQDN(c.Target)
			}
		}
	}

	return res
}

// iterativeResolve walks the DNS hierarchy from root (or TLD when root zone
// cache has glue), following NS referrals at each level, until it gets an
// authoritative answer for name/qtype.
func (r *Resolver) iterativeResolve(name string, qtype uint16) (*dns.Msg, error) {
	servers, err := r.startingServers(name)
	if err != nil {
		return nil, err // unknown TLD
	}

	cnameHops := 0
	for depth := 0; depth < r.maxDepth; depth++ {
		resp, err := r.query(name, qtype, servers)
		if err != nil {
			return nil, err
		}

		switch resp.Rcode {
		case dns.RcodeNameError: // NXDOMAIN
			return nil, &NXDomainError{Name: name}
		case dns.RcodeServerFailure:
			return nil, fmt.Errorf("SERVFAIL for %s (all authoritative servers failed)", name)
		}

		if len(resp.Answer) > 0 {
			if qtype != dns.TypeCNAME {
				if target := extractCNAMETarget(resp); target != "" {
					if cnameHops >= 8 {
						return nil, fmt.Errorf("CNAME chain too deep for %s", name)
					}
					name = dns.Fqdn(strings.ToLower(target))
					cnameHops++
					depth = -1 // post-increment brings this to 0 at loop top
					servers, err = r.startingServers(name)
					if err != nil {
						return nil, err
					}
					continue
				}
			}
			return resp, nil
		}

		// AA=true, empty Answer → NODATA (type absent, domain exists).
		// Or if it contains an SOA record in Authority section, it's a terminal response.
		// (Many DNS servers return NXDOMAIN/NODATA without AA=true but with an SOA)
		if resp.Authoritative || hasSOA(resp) {
			return resp, nil
		}

		// Non-authoritative, no Answer → NS referral.
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

// startingServers returns the initial server list for iterativeResolve.
func (r *Resolver) startingServers(name string) ([]string, error) {
	tld := extractTLD(name)
	if r.rootZone != nil {
		if !r.rootZone.KnownTLD(tld) {
			return nil, &NXDomainError{Name: name}
		}
		if ips, ok := r.rootZone.NSForTLD(tld); ok {
			return ips, nil
		}
	}
	return []string{randomRootServer() + ":53"}, nil
}

// query sends name/qtype to each server in shuffled order with UDP,
// falling back to TCP on truncation.
func (r *Resolver) query(name string, qtype uint16, servers []string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false
	m.SetEdns0(1232, false)

	shuffled := make([]string, len(servers))
	copy(shuffled, servers)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	var lastErr error
	var servfailResp *dns.Msg

	for _, srv := range shuffled {
		for try := 0; try <= r.retries; try++ {
			resp, _, err := r.udp.Exchange(m, srv)
			if err != nil {
				lastErr = err
				continue
			}
			if resp.Truncated {
				resp, _, err = r.tcp.Exchange(m, srv)
				if err != nil {
					lastErr = err
					continue
				}
			}
			if resp.Rcode == dns.RcodeServerFailure {
				lastErr = fmt.Errorf("SERVFAIL from %s for %s %s",
					srv, name, dns.TypeToString[qtype])
				servfailResp = resp
				break
			}
			return resp, nil
		}
	}

	if servfailResp != nil {
		return servfailResp, nil
	}
	return nil, fmt.Errorf("all servers failed for %s %s: %w",
		name, dns.TypeToString[qtype], lastErr)
}

// resolveNStoIPs maps NS hostnames to IP address strings using glue or public resolvers.
func (r *Resolver) resolveNStoIPs(names []string, glue map[string][]string) []string {
	limit := 4
	if len(names) < limit {
		limit = len(names)
	}

	var ips []string
	seen := make(map[string]bool)

	for _, name := range names[:limit] {
		if addrs, ok := glue[name]; ok {
			for _, ip := range addrs {
				if !seen[ip] {
					ips = append(ips, ip)
					seen[ip] = true
				}
			}
			continue
		}
		
		// Glueless — ask a public recursive resolver for NS hostname A records.
		for _, pub := range publicFallbackResolvers {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(name), dns.TypeA)
			m.RecursionDesired = true
			
			resp, _, err := r.udp.Exchange(m, pub)
			// TCP fallback for truncated responses on public resolvers
			if err == nil && resp != nil && resp.Truncated {
				resp, _, err = r.tcp.Exchange(m, pub)
			}
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

// hasSOA returns true if the authority section contains an SOA record.
// This identifies NODATA/NXDOMAIN responses that lack the AA bit.
func hasSOA(msg *dns.Msg) bool {
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

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

func extractCNAMETarget(msg *dns.Msg) string {
	for _, rr := range msg.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			return trimFQDN(c.Target)
		}
	}
	return ""
}

func addPort(ips []string, port string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
			out = append(out, "["+ip+"]:"+port)
		} else {
			out = append(out, ip+":"+port)
		}
	}
	return out
}

