// File    : validator.go
// Version : 1.5.0
// Modified: 2026-04-01 20:00 UTC
//
// Changes:
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
//          Graceful shutdown: RunBatch accepts a context. Before launching
//          each new domain goroutine it checks ctx.Done(). On cancellation
//          it stops queuing new work but calls wg.Wait() so every goroutine
//          that is already running completes and persists its result. The
//          caller (runCheck/runStaleRevalidation) then exports and closes.
//
//          RDAP throttle handling: when the RDAP registry host for a domain
//          is in a 429 backoff window, the RDAP check is silently skipped
//          (RDAPSkipped=true). DNS and TOP-N still run normally. The domain
//          is scored and persisted — it can reach ACTIVE without RDAP.

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
// When the RDAP registry for this domain is throttled, the RDAP check is
// skipped (result.RDAPSkipped = true) but every other check runs normally.
// The domain is always scored and written to the store — it can reach ACTIVE
// on DNS evidence alone.
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

	rdapCh := make(chan rdapOut, 1)
	dnsCh  := make(chan dnsOut,  1)

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

	// --- DNS delegation + resolution (iterative, always runs) ---
	go func() {
		select {
		case <-ctx.Done():
			dnsCh <- dnsOut{res: &ResolveResult{Errors: []string{"timeout"}}}
		default:
			dnsCh <- dnsOut{res: v.resolver.CheckDomain(apex)}
		}
	}()

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

	// Collect DNS result.
	select {
	case out := <-dnsCh:
		r := out.res
		result.HasNS     = r.HasNS
		result.HasA      = r.HasA
		result.HasAAAA   = r.HasAAAA
		result.NSRecords = r.NS
		result.Errors    = append(result.Errors, r.Errors...)
	case <-ctx.Done():
		result.Errors = append(result.Errors, "dns: context deadline exceeded")
	}

	// Score and assign final status based on whatever sources are available.
	Score(result, v.cfg.Validation.MinActiveScore)
	return result
}

