// File    : progress.go
// Version : 1.2.0
// Modified: 2026-04-01 18:00 UTC
//
// Changes:
//   v1.2.0 - 2026-04-01 - Removed postponed counter; track rdap_skipped instead
//   v1.1.0 - 2026-04-01 - Track and display postponed domain count
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Progress and diagnostic reporter for validation runs.
//          Two verbosity levels:
//
//            normal  — one summary line per batch tick (every 100 domains
//                      or on completion): count, rate, ETA, status breakdown.
//
//            verbose — additionally prints one line per domain showing its
//                      score, status, which sources fired, and any errors.
//
//          Domains where RDAP was throttled are counted in rdapSkipped but
//          still land in the normal status buckets — they score and persist
//          like any other domain, just without the RDAP contribution.
//
//          All output goes to stderr so stdout stays clean for piping.
//          Safe for concurrent use (sync.Mutex on counters).

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const progressTickEvery = 100 // print a summary line every N domains in normal mode

// Progress tracks and reports validation progress.
type Progress struct {
	verbose  bool
	total    int       // total domains queued for this batch
	start    time.Time

	// atomic counters — safe to increment from any goroutine
	done        atomic.Int64
	active      atomic.Int64
	inactive    atomic.Int64
	stale       atomic.Int64
	unknown     atomic.Int64
	errors      atomic.Int64
	rdapSkipped atomic.Int64 // domains where RDAP was skipped due to throttle backoff

	mu sync.Mutex // protects the ticker logic only
}

// NewProgress creates a Progress reporter.
// total is the number of domains in this batch (0 = unknown).
func NewProgress(verbose bool, total int) *Progress {
	return &Progress{
		verbose: verbose,
		total:   total,
		start:   time.Now(),
	}
}

// Start prints the batch header.
func (p *Progress) Start() {
	if p.total > 0 {
		p.printf("  ┌─ starting batch: %d domain(s) — verbose=%v\n", p.total, p.verbose)
	} else {
		p.printf("  ┌─ starting batch (unknown size) — verbose=%v\n", p.verbose)
	}
}

// Domain is called once per validated domain with its full result.
// Always updates counters; prints a per-domain line only in verbose mode.
func (p *Progress) Domain(r *ValidationResult) {
	p.done.Add(1)
	n := p.done.Load()

	if r.RDAPSkipped {
		p.rdapSkipped.Add(1)
	}

	// All domains — including those with RDAP skipped — land in the normal
	// status buckets. The throttle only affects the score, not the reporting path.
	switch r.Status {
	case StatusActive:
		p.active.Add(1)
	case StatusInactive:
		p.inactive.Add(1)
	case StatusStale:
		p.stale.Add(1)
	default:
		p.unknown.Add(1)
	}
	if len(r.Errors) > 0 {
		p.errors.Add(1)
	}

	if p.verbose {
		p.printDomain(r, n)
	}

	if !p.verbose {
		p.maybeTick(n)
	}
}

// Finish prints the final summary block.
func (p *Progress) Finish() {
	n := p.done.Load()
	elapsed := time.Since(p.start)
	rate := float64(n) / elapsed.Seconds()

	p.printf("  └─ done: %d domain(s) in %s (%.1f/s)\n", n, fmtDuration(elapsed), rate)
	p.printf("     active=%-6d inactive=%-6d stale=%-6d unknown=%-6d errors=%d",
		p.active.Load(), p.inactive.Load(), p.stale.Load(), p.unknown.Load(), p.errors.Load())

	// Only print the rdap_skipped column when relevant — keeps clean runs clean.
	if sk := p.rdapSkipped.Load(); sk > 0 {
		p.printf("  rdap_skipped=%d (scored without RDAP — will fill in next cycle)", sk)
	}
	p.printf("\n")
}

// --- internal helpers ---

// maybeTick prints a summary line in normal mode every progressTickEvery domains.
func (p *Progress) maybeTick(n int64) {
	p.mu.Lock()
	tick := n%progressTickEvery == 0 || int(n) == p.total
	p.mu.Unlock()
	if tick {
		p.printSummaryLine(n)
	}
}

// printDomain prints one line per domain (verbose mode).
// Format:  [  42/1000]  ACTIVE  210  google.com  (TOP_N,RDAP,DNS_DELEGATION,DNS_RESOLUTION)
func (p *Progress) printDomain(r *ValidationResult, n int64) {
	idx := fmt.Sprintf("[%*d/%d]", len(fmt.Sprint(p.total)), n, p.total)
	if p.total == 0 {
		idx = fmt.Sprintf("[%d]", n)
	}
	status := fmt.Sprintf("%-8s", r.Status)

	sources := "-"
	if len(r.Sources) > 0 {
		ss := make([]string, len(r.Sources))
		for i, s := range r.Sources {
			ss[i] = string(s)
		}
		sources = strings.Join(ss, ",")
	}

	line := fmt.Sprintf("  %s  %s  %3d  %-40s  (%s)",
		idx, status, r.Score, r.Domain, sources)

	if len(r.Errors) > 0 {
		line += "  !! " + strings.Join(r.Errors, "; ")
	}
	p.printf("%s\n", line)
}

// printSummaryLine prints a one-line rolling summary (normal mode).
func (p *Progress) printSummaryLine(n int64) {
	elapsed := time.Since(p.start)
	rate := float64(n) / elapsed.Seconds()

	pct := ""
	eta := ""
	if p.total > 0 {
		pct = fmt.Sprintf(" %3.0f%%", float64(n)/float64(p.total)*100)
		remaining := int64(p.total) - n
		if rate > 0 {
			secs := float64(remaining) / rate
			eta = "  eta " + fmtDuration(time.Duration(secs)*time.Second)
		}
	}

	skipped := p.rdapSkipped.Load()
	skStr := ""
	if skipped > 0 {
		skStr = fmt.Sprintf("  rdap_skipped=%d", skipped)
	}

	p.printf("  progress: %d/%d%s  active=%-6d inactive=%-6d  %.1f/s%s%s\n",
		n, p.total, pct,
		p.active.Load(), p.inactive.Load(),
		rate, eta, skStr)
}

// printf writes to stderr (keeps stdout clean for piping).
func (p *Progress) printf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// fmtDuration formats a duration as a compact human string (e.g. "2m04s").
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%02ds", m, s)
}

