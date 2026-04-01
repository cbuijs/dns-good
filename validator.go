// File    : validator.go
// Version : 1.0.0
// Modified: 2026-04-01 12:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Orchestrates per-domain validation across all four sources
//          (TOP-N, RDAP, DNS delegation, DNS resolution) and persists
//          results via the store. A semaphore channel limits concurrency
//          to cfg.Validation.Workers goroutines at any time. Each domain
//          gets a hard deadline of cfg.Validation.Timeout.

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
}

// NewValidator constructs a Validator from the given config and store.
func NewValidator(cfg *Config, store *Store) *Validator {
	return &Validator{
		cfg:      cfg,
		store:    store,
		resolver: NewResolver(cfg.DNS.MaxDepth, cfg.DNS.Retries, cfg.DNS.Timeout),
		rdap:     NewRDAPClient(cfg),
		topn:     NewTopN(cfg),
	}
}

// RunBatch fetches all UNKNOWN/STALE domains from the store and validates
// them concurrently. Returns the number of domains processed.
func (v *Validator) RunBatch() int {
	// Fetch a large page of work; RunBatch can be called in a loop if needed.
	entries, err := v.store.GetNeedingValidation(10_000)
	if err != nil {
		log.Printf("validator: fetch work: %v", err)
		return 0
	}
	if len(entries) == 0 {
		return 0
	}

	log.Printf("validator: processing %d domain(s) with %d worker(s)",
		len(entries), v.cfg.Validation.Workers)

	sem := make(chan struct{}, v.cfg.Validation.Workers)
	var wg sync.WaitGroup
	var processed atomic.Int64

	for _, e := range entries {
		wg.Add(1)
		sem <- struct{}{} // acquire
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }() // release

			result := v.validateOne(domain)
			if err := v.store.Upsert(result); err != nil {
				log.Printf("validator: upsert %s: %v", domain, err)
			}
			processed.Add(1)
		}(e.Domain)
	}

	wg.Wait()
	return int(processed.Load())
}

// validateOne runs all four checks for a single domain within a deadline.
// Non-fatal errors from individual checks are collected in result.Errors.
func (v *Validator) validateOne(domain string) *ValidationResult {
	ctx, cancel := context.WithTimeout(context.Background(), v.cfg.Validation.Timeout)
	defer cancel()

	apex := extractApex(domain)
	result := &ValidationResult{
		Domain:    domain,
		Apex:      apex,
		CheckedAt: time.Now(),
	}

	// Use a channel to respect the overall context deadline. Each check runs
	// in its own goroutine; the first to finish writes to the respective field.
	// If ctx expires, partial results are still scored.

	type rdapOut struct{ res RDAPResult }
	type dnsOut  struct{ res *ResolveResult }

	rdapCh := make(chan rdapOut, 1)
	dnsCh  := make(chan dnsOut,  1)

	// --- TOP-N (in-memory, non-blocking) ---
	rank := v.topn.Rank(apex)
	result.InTopN   = rank > 0
	result.TopNRank = rank

	// --- RDAP (network, runs concurrently with DNS) ---
	go func() {
		select {
		case <-ctx.Done():
			rdapCh <- rdapOut{res: RDAPResult{Error: "timeout"}}
		default:
			rdapCh <- rdapOut{res: v.rdap.Check(apex)}
		}
	}()

	// --- DNS delegation + resolution (iterative, concurrent with RDAP) ---
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
		if r.Error != "" {
			result.Errors = append(result.Errors, "rdap: "+r.Error)
		} else {
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
		result.HasNS   = r.HasNS
		result.HasA    = r.HasA
		result.HasAAAA = r.HasAAAA
		result.NSRecords = r.NS
		result.Errors  = append(result.Errors, r.Errors...)
	case <-ctx.Done():
		result.Errors = append(result.Errors, "dns: context deadline exceeded")
	}

	// Score everything and set final status.
	Score(result)
	return result
}

