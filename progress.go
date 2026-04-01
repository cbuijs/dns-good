// File    : progress.go
// Version : 1.3.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.3.0 - 2026-04-01 - Standardised file header
//   v1.2.0 - 2026-04-01 - Removed postponed counter; track rdap_skipped instead
//   v1.1.0 - 2026-04-01 - Track and display postponed domain count
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Progress and diagnostic reporter for validation runs.

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const progressTickEvery = 100

type Progress struct {
	verbose  bool
	total    int
	start    time.Time
	done        atomic.Int64
	active      atomic.Int64
	inactive    atomic.Int64
	stale       atomic.Int64
	unknown     atomic.Int64
	errors      atomic.Int64
	rdapSkipped atomic.Int64
	mu sync.Mutex
}

func NewProgress(verbose bool, total int) *Progress {
	return &Progress{ verbose: verbose, total: total, start: time.Now() }
}

func (p *Progress) Start() {
	if p.total > 0 {
		p.printf("  ┌─ starting batch: %d domain(s) — verbose=%v\n", p.total, p.verbose)
	} else {
		p.printf("  ┌─ starting batch (unknown size) — verbose=%v\n", p.verbose)
	}
}

func (p *Progress) Domain(r *ValidationResult) {
	p.done.Add(1)
	n := p.done.Load()

	if r.RDAPSkipped { p.rdapSkipped.Add(1) }

	switch r.Status {
	case StatusActive: p.active.Add(1)
	case StatusInactive: p.inactive.Add(1)
	case StatusStale: p.stale.Add(1)
	default: p.unknown.Add(1)
	}
	if len(r.Errors) > 0 { p.errors.Add(1) }

	if p.verbose { p.printDomain(r, n) }
	if !p.verbose { p.maybeTick(n) }
}

func (p *Progress) Finish() {
	n := p.done.Load()
	elapsed := time.Since(p.start)
	rate := float64(n) / elapsed.Seconds()

	p.printf("  └─ done: %d domain(s) in %s (%.1f/s)\n", n, fmtDuration(elapsed), rate)
	p.printf("     active=%-6d inactive=%-6d stale=%-6d unknown=%-6d errors=%d",
		p.active.Load(), p.inactive.Load(), p.stale.Load(), p.unknown.Load(), p.errors.Load())

	if sk := p.rdapSkipped.Load(); sk > 0 {
		p.printf("  rdap_skipped=%d (scored without RDAP — will fill in next cycle)", sk)
	}
	p.printf("\n")
}

func (p *Progress) maybeTick(n int64) {
	p.mu.Lock()
	tick := n%progressTickEvery == 0 || int(n) == p.total
	p.mu.Unlock()
	if tick { p.printSummaryLine(n) }
}

func (p *Progress) printDomain(r *ValidationResult, n int64) {
	idx := fmt.Sprintf("[%*d/%d]", len(fmt.Sprint(p.total)), n, p.total)
	if p.total == 0 { idx = fmt.Sprintf("[%d]", n) }
	status := fmt.Sprintf("%-8s", r.Status)

	sources := "-"
	if len(r.Sources) > 0 {
		ss := make([]string, len(r.Sources))
		for i, s := range r.Sources { ss[i] = string(s) }
		sources = strings.Join(ss, ",")
	}

	line := fmt.Sprintf("  %s  %s  %3d  %-40s  (%s)", idx, status, r.Score, r.Domain, sources)
	if len(r.Errors) > 0 { line += "  !! " + strings.Join(r.Errors, "; ") }
	p.printf("%s\n", line)
}

func (p *Progress) printSummaryLine(n int64) {
	elapsed := time.Since(p.start)
	rate := float64(n) / elapsed.Seconds()

	pct, eta := "", ""
	if p.total > 0 {
		pct = fmt.Sprintf(" %3.0f%%", float64(n)/float64(p.total)*100)
		if rate > 0 {
			eta = "  eta " + fmtDuration(time.Duration(int64(p.total)-n)*time.Second)
		}
	}

	skStr := ""
	if sk := p.rdapSkipped.Load(); sk > 0 { skStr = fmt.Sprintf("  rdap_skipped=%d", sk) }

	p.printf("  progress: %d/%d%s  active=%-6d inactive=%-6d  %.1f/s%s%s\n",
		n, p.total, pct, p.active.Load(), p.inactive.Load(), rate, eta, skStr)
}

func (p *Progress) printf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute { return fmt.Sprintf("%ds", int(d.Seconds())) }
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

