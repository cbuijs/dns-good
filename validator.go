// File    : validator.go
// Version : 1.7.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.7.0 - 2026-04-01 - Merge HasCNAME and CNAMETarget from sub-domain and apex checks
//   v1.6.0 - 2026-04-01 - Also run DNS checks on the submitted domain when it
//                          differs from the PSL apex
//   v1.5.0 - 2026-04-01 - RunBatch accepts context.Context; graceful shutdown
//   v1.4.0 - 2026-04-01 - RDAP throttle skips only RDAP; DNS+TOP-N still run and score
//   v1.3.0 - 2026-04-01 - Skip + postpone domains when RDAP host is throttled
//   v1.2.0 - 2026-04-01 - Pass MinActiveScore through to Score()
//   v1.1.0 - 2026-04-01 - resolver/rdap/topn lifted to main; verbose flag added
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Orchestrates per-domain validation across all four sources
//          (TOP-N, RDAP, DNS delegation, DNS resolution) and persists
//          results via the store.

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
// pre-initialised long-lived components.
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

// RunBatch fetches UNKNOWN/STALE domains from the store and validates them.
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
		sem <- struct{}{}
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
	subDNSCh  := make(chan dnsOut, 1)
	checkSub  := domain != apex

	// --- TOP-N ---
	rank := v.topn.Rank(apex)
	result.InTopN   = rank > 0
	result.TopNRank = rank

	// --- RDAP ---
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

	// --- DNS: apex ---
	go func() {
		select {
		case <-ctx.Done():
			apexDNSCh <- dnsOut{res: &ResolveResult{Errors: []string{"timeout"}}}
		default:
			apexDNSCh <- dnsOut{res: v.resolver.CheckDomain(apex)}
		}
	}()

	// --- DNS: submitted domain ---
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
		subDNSCh <- dnsOut{res: nil}
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
		result.HasNS       = r.HasNS
		result.HasA        = r.HasA
		result.HasAAAA     = r.HasAAAA
		result.HasCNAME    = r.HasCNAME
		result.CNAMETarget = r.CNAMETarget
		result.NSRecords   = r.NS
		result.Errors      = append(result.Errors, r.Errors...)
	case <-ctx.Done():
		result.Errors = append(result.Errors, "dns (apex): context deadline exceeded")
	}

	// Collect submitted-domain DNS result and merge with OR logic.
	select {
	case out := <-subDNSCh:
		if r := out.res; r != nil {
			if r.HasNS {
				result.HasNS = true
				result.NSRecords = append(result.NSRecords, r.NS...)
			}
			if r.HasA { result.HasA = true }
			if r.HasAAAA { result.HasAAAA = true }
			if r.HasCNAME {
				result.HasCNAME = true
				result.CNAMETarget = r.CNAMETarget
			}
			for _, e := range r.Errors {
				result.Errors = append(result.Errors, "dns (sub): "+e)
			}
		}
	case <-ctx.Done():
		result.Errors = append(result.Errors, "dns (sub): context deadline exceeded")
	}

	Score(result, v.cfg.Validation.MinActiveScore)
	return result
}

