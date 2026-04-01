// File    : validator.go
// Version : 1.6.0
// Modified: 2026-04-01 21:00 UTC
//
// Changes:
//   v1.6.0 - 2026-04-01 - Also run DNS checks on the submitted domain when it
//                          differs from the PSL apex; fixes false-INACTIVE for
//                          separately delegated subdomains (e.g. arc2.msn.com)
//   v1.5.0 - 2026-04-01 - RunBatch accepts context.Context; stops queuing new
//                          domains on cancellation while in-flight work finishes
//   v1.4.0 - 2026-04-01 - RDAP throttle skips only RDAP; DNS+TOP-N still run and score
//   v1.3.0 - 2026-04-01 - Skip + postpone domains when RDAP host is throttled
//   v1.2.0 - 2026-04-01 - Pass MinActiveScore through to Score()
//   v1.1.0 - 2026-04-01 - resolver/rdap/topn lifted to main; verbose flag added
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Orchestrates per-domain validation across all four sources
//          (TOP-N, RDAP, DNS delegation, DNS resolution) and persists
//          results via the store. A semaphore channel limits concurrency
//          to cfg.Validation.Workers goroutines at any time. Each domain
//          gets a hard deadline of cfg.Validation.Timeout.
//
//          Subdomain DNS: RDAP and TOP-N are registry-level concepts and
//          always use the PSL apex. DNS delegation and resolution are
//          checked at BOTH the apex and the submitted domain when they
//          differ. This means a separately delegated subdomain like
//          arc2.msn.com contributes its own NS and A records to the score
//          even when the apex (msn.com) has no direct A records at the zone
//          root (e.g. CDN ALIAS/ANAME setups that only resolve for recursive
//          clients, not iterative ones).
//
//          Graceful shutdown: RunBatch accepts a context. Before launching
//          each new domain goroutine it checks ctx.Done(). On cancellation
//          it stops queuing new work but calls wg.Wait() so every goroutine
//          that is already running completes and persists its result.
//
//          RDAP throttle handling: when the RDAP registry host for a domain
//          is in a 429 backoff window, the RDAP check is silently skipped
//          (RDAPSkipped=true). DNS and TOP-N still run normally.

package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Validator wires together all data sources and runs batch validations.
type Validator struct {
	cfg      *Config
	store    *Store
	resolver *Resolver
	rdap     *RDAPClient
	topn     *TopN
	verbose  bool
}

// NewValidator constructs a Validator from the given config, store, and
// pre-initialised long-lived components. resolver, rdap, and topn are
// created once in main and reused across runs so their in-memory state
// (parsed TOP-N map, RDAP bootstrap, DNS client) survives between cycles.
func NewValidator(cfg *Config, store *Store, resolver *Resolver, rdap *RDAPClient, topn *TopN, verbose bool) *Validator {
	return &Validator{
		cfg:      cfg,
		store:    store,
		resolver: resolver,
		rdap:     rdap,
		topn:     topn,
		verbose:  verbose,
	}
}

// RunBatch fetches UNKNOWN/STALE domains from the store and validates them
// concurrently. batch limits how many are processed in one call; 0 = unlimited.
// Returns the number of domains processed.
//
// Shutdown behaviour: when ctx is cancelled (e.g. SIGINT), the loop stops
// launching new domain goroutines. Any goroutine already running is allowed
// to finish — it has its own per-domain deadline and will persist its result.
// wg.Wait() ensures we never return with work still in-flight.
func (v *Validator) RunBatch(ctx context.Context, batch int) int {
	entries, err := v.store.GetNeedingValidation(batch)
	if err != nil {
		log.Printf("validator: fetch work: %v", err)
		return 0
	}
	if len(entries) == 0 {
		log.Println("validator: nothing to validate")
		return 0
	}

	prog := NewProgress(v.verbose, len(entries))
	prog.Start()

	sem := make(chan struct{}, v.cfg.Validation.Workers)
	var wg sync.WaitGroup
	var processed atomic.Int64

	for _, e := range entries {
		// Check for shutdown before acquiring a worker slot — this is the
		// earliest possible point to stop without wasting any resources.
		// Goroutines already running are unaffected and will finish normally.
		select {
		case <-ctx.Done():
			log.Printf("validator: shutdown signal — waiting for %d in-flight goroutine(s) to finish",
				v.cfg.Validation.Workers-len(sem))
			wg.Wait()
			prog.Finish()
			return int(processed.Load())
		default:
		}

		wg.Add(1)
		sem <- struct{}{} // acquire worker slot (blocks if all workers are busy)
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := v.validateOne(domain)
			prog.Domain(result)
			if err := v.store.Upsert(result); err != nil {
				log.Printf("validator: upsert %s: %v", domain, err)
			}
			processed.Add(1)
		}(e.Domain)
	}

	wg.Wait()
	prog.Finish()
	return int(processed.Load())
}

// validateOne runs all available checks for a single domain within a deadline.
// Non-fatal errors from individual checks are collected in result.Errors.
//
// DNS strategy: RDAP and TOP-N are always checked against the PSL apex —
// they are registry-level signals. DNS is checked against BOTH the apex
// and the submitted domain when they differ, and the results are merged
// with OR logic (evidence from either counts). This handles separately
// delegated subdomains like arc2.msn.com, whose own NS and A records are
// real live-domain evidence that the apex-only check would miss entirely.
func (v *Validator) validateOne(domain string) *ValidationResult {
	ctx, cancel := context.WithTimeout(context.Background(), v.cfg.Validation.Timeout)
	defer cancel()

	apex := extractApex(domain)
	result := &ValidationResult{
		Domain:    domain,
		Apex:      apex,
		CheckedAt: time.Now(),
	}

	type rdapOut struct{ res RDAPResult }
	type dnsOut  struct{ res *ResolveResult }

	rdapCh    := make(chan rdapOut, 1)
	apexDNSCh := make(chan dnsOut,  1)

	// subDNSCh carries the result of checking the submitted domain directly.
	// It is only used when the submitted domain differs from the PSL apex.
	// When they are the same, we send a nil sentinel so the collect step
	// below is unconditional and doesn't need a special case.
	subDNSCh := make(chan dnsOut, 1)
	checkSub := domain != apex

	// --- TOP-N (in-memory, non-blocking) ---
	rank := v.topn.Rank(apex)
	result.InTopN   = rank > 0
	result.TopNRank = rank

	// --- RDAP (network, concurrent with DNS) ---
	// If the registry host for this apex is in a 429 backoff window, skip the
	// RDAP goroutine entirely — no request, no wasted wait. Feed a sentinel
	// straight into the channel so the select below drains cleanly.
	rdapThrottled := v.rdap.IsThrottled(apex)
	if rdapThrottled {
		rdapCh <- rdapOut{res: RDAPResult{Throttled: true}}
	} else {
		go func() {
			select {
			case <-ctx.Done():
				rdapCh <- rdapOut{res: RDAPResult{Error: "timeout"}}
			default:
				rdapCh <- rdapOut{res: v.rdap.Check(apex)}
			}
		}()
	}

	// --- DNS: apex (always) ---
	go func() {
		select {
		case <-ctx.Done():
			apexDNSCh <- dnsOut{res: &ResolveResult{Errors: []string{"timeout"}}}
		default:
			apexDNSCh <- dnsOut{res: v.resolver.CheckDomain(apex)}
		}
	}()

	// --- DNS: submitted domain (only when it differs from the apex) ---
	// Examples where this fires:
	//   arc2.msn.com  — separately delegated zone inside msn.com with own A records
	//   cdn.example.co.uk — own NS delegation under a compound-TLD apex
	// Examples where this does NOT fire (domain == apex):
	//   google.com, msn.com, example.co.uk — submitted at the registered apex
	if checkSub {
		go func() {
			select {
			case <-ctx.Done():
				subDNSCh <- dnsOut{res: &ResolveResult{Errors: []string{"timeout"}}}
			default:
				subDNSCh <- dnsOut{res: v.resolver.CheckDomain(domain)}
			}
		}()
	} else {
		subDNSCh <- dnsOut{res: nil} // sentinel: no sub-check needed
	}

	// Collect RDAP result.
	select {
	case out := <-rdapCh:
		r := out.res
		switch {
		case r.Throttled:
			result.RDAPSkipped = true
			result.Errors = append(result.Errors, "rdap: skipped (throttled — will retry next cycle)")
		case r.Error != "":
			result.Errors = append(result.Errors, "rdap: "+r.Error)
		default:
			result.RDAPActive = r.Active
			result.RDAPStatus = r.StatusText
			result.RDAPExpiry = r.Expiry
		}
	case <-ctx.Done():
		result.Errors = append(result.Errors, "rdap: context deadline exceeded")
	}

	// Collect apex DNS result.
	select {
	case out := <-apexDNSCh:
		r := out.res
		result.HasNS     = r.HasNS
		result.HasA      = r.HasA
		result.HasAAAA   = r.HasAAAA
		result.NSRecords = r.NS
		result.Errors    = append(result.Errors, r.Errors...)
	case <-ctx.Done():
		result.Errors = append(result.Errors, "dns (apex): context deadline exceeded")
	}

	// Collect submitted-domain DNS result and merge with OR logic.
	// Any positive DNS evidence from the submitted domain is treated as
	// equivalent to evidence from the apex — the domain is live if either
	// the apex or the submitted subdomain resolves.
	select {
	case out := <-subDNSCh:
		if r := out.res; r != nil {
			if r.HasNS {
				result.HasNS = true
				result.NSRecords = append(result.NSRecords, r.NS...)
			}
			if r.HasA {
				result.HasA = true
			}
			if r.HasAAAA {
				result.HasAAAA = true
			}
			// Prefix sub-domain errors so they're distinguishable in logs.
			for _, e := range r.Errors {
				result.Errors = append(result.Errors, "dns (sub): "+e)
			}
		}
	case <-ctx.Done():
		result.Errors = append(result.Errors, "dns (sub): context deadline exceeded")
	}

	// Score and assign final status based on whatever sources are available.
	Score(result, v.cfg.Validation.MinActiveScore)
	return result
}

