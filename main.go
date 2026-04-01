// File    : main.go
// Version : 1.5.0
// Modified: 2026-04-01 20:00 UTC
//
// Changes:
//   v1.5.0 - 2026-04-01 - Graceful shutdown via context: Ctrl-C finishes in-flight
//                          work, always exports and closes DB cleanly; second signal
//                          force-exits immediately
//   v1.4.0 - 2026-04-01 - Wire up RootZone; pass it to NewResolver
//   v1.3.0 - 2026-04-01 - Added -db flag to override db.path from config
//   v1.2.0 - 2026-04-01 - Added -reset flag to wipe DB and output dir before a run
//   v1.1.0 - 2026-04-01 - Added -output and -verbose flags; verbose threaded through
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Entry point for dns-good. Parses CLI flags, wires up all
//          components, and dispatches to one of three run modes:
//
//            check  — validate a one-shot list of domains and exit
//            run    — continuous revalidation loop (daemon mode)
//            stats  — print repository statistics and exit
//
//          Graceful shutdown: SIGINT/SIGTERM cancels a shared context that
//          flows through RunBatch. New goroutines stop being launched; any
//          domain already in-flight finishes normally. ExportLists and
//          store.Close always run on the way out — the DB and output files
//          are always consistent. A second signal force-exits immediately.
//
//          Build:  go build -o dns-good .
//          Usage:  ./dns-good -help

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// --- CLI flags ---
	configPath := flag.String("config",  "config.yaml", "Path to YAML config file")
	mode       := flag.String("mode",    "check",       "Run mode: check | run | stats")
	inputFile  := flag.String("input",   "",            "File with one domain per line (check/run mode)")
	workers    := flag.Int(   "workers",  0,            "Override validation worker count (0 = use config)")
	verbose    := flag.Bool(  "verbose", false,         "Print one progress line per domain (score, status, sources, errors)")
	outputDir  := flag.String("output",  "",            "Override output directory for status text files (empty = use config)")
	dbPath     := flag.String("db",      "",            "Override database file path from config (empty = use config)")
	reset      := flag.Bool(  "reset",   false,         "Wipe the database and output directory before running (fresh start)")
	batch      := flag.Int(   "batch",    0,            "Max domains to validate per run (0 = unlimited)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `dns-good — DNS domain validation repository

Usage: dns-good [flags]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Modes:
  check   Read domains from -input file (or stdin if omitted), validate them
          once, persist results, and exit. Good for cron / one-shot runs.

  run     Like check but loops forever: after processing the input file it
          waits revalidate_delay, marks stale entries, and repeats.
          Receives SIGINT/SIGTERM for clean shutdown.

  stats   Print per-status domain counts from the repository and exit.
`)
	}
	flag.Parse()

	// --- Graceful shutdown context ---
	// A single context covers all modes. The signal goroutine cancels it on the
	// first SIGINT/SIGTERM; RunBatch checks it before launching each new domain
	// goroutine. In-flight work finishes normally; ExportLists and store.Close
	// always run via the deferred calls below. A second signal force-exits.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2) // buffered 2 so the second signal never blocks
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("signal %s received — finishing in-flight work then exiting cleanly (send again to force)", sig)
		cancel() // unblocks ctx.Done() in RunBatch
		// Second signal: skip the clean path and exit immediately.
		sig = <-sigCh
		log.Printf("second signal %s received — forcing exit now", sig)
		os.Exit(1)
	}()

	// --- Config ---
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// CLI overrides — applied after config load so flags always win.
	if *workers > 0 {
		cfg.Validation.Workers = *workers
	}
	if *outputDir != "" {
		cfg.Output.Dir = *outputDir
	}
	// -db overrides db.path from the YAML config. Handy when running
	// multiple instances side-by-side or pointing at a shared/network DB
	// without having to maintain separate config files.
	if *dbPath != "" {
		cfg.DB.Path = *dbPath
	}

	// Reset wipes the database file and output directory before anything else
	// runs. The store is opened fresh afterwards so the schema is re-applied.
	// Note: uses cfg.DB.Path, which has already been overridden above if -db
	// was supplied — so -reset + -db correctly wipes the right file.
	if *reset {
		doReset(cfg)
	}

	// --- Storage ---
	store, err := NewStore(cfg.DB.Path)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	// Close is deferred here so it always runs — normal exit, signal, or panic.
	defer func() {
		log.Println("shutdown: closing database")
		store.Close()
	}()

	// Long-lived components — created once and reused across every run cycle.
	// This keeps the Tranco TOP-N map, RDAP bootstrap, root zone cache, and
	// DNS client state in memory between runs instead of re-initialising from
	// disk each time.
	rootZone := NewRootZone(cfg)
	if err := rootZone.Ensure(); err != nil {
		// Non-fatal — the resolver falls back to normal root-server behaviour.
		log.Printf("rootzone: load failed (%v) — falling back to root servers", err)
	}
	resolver := NewResolver(cfg.DNS.MaxDepth, cfg.DNS.Retries, cfg.DNS.Timeout, rootZone)
	rdap     := NewRDAPClient(cfg)
	topn     := NewTopN(cfg)

	switch *mode {

	// ------------------------------------------------------------------
	case "stats":
		runStats(store)

	// ------------------------------------------------------------------
	case "check":
		// Input file is optional — without one we still revalidate any
		// STALE/UNKNOWN entries that are already in the store.
		domains := loadDomains(*inputFile)
		runCheck(ctx, cfg, store, resolver, rdap, topn, domains, *verbose, *batch)

	// ------------------------------------------------------------------
	case "run":
		domains := loadDomains(*inputFile)

		log.Printf("dns-good running in daemon mode (workers=%d, stale_ttl=%s, delay=%s)",
			cfg.Validation.Workers, cfg.Validation.StaleTTL, cfg.Validation.RevalidateDelay)

		for {
			n, err := store.MarkStaleEntries(cfg.Validation.StaleTTL)
			if err != nil {
				log.Printf("mark stale: %v", err)
			} else if n > 0 {
				log.Printf("marked %d entries as STALE", n)
			}

			if len(domains) > 0 {
				runCheck(ctx, cfg, store, resolver, rdap, topn, domains, *verbose, *batch)
			} else {
				runStaleRevalidation(ctx, cfg, store, resolver, rdap, topn, *verbose, *batch)
			}

			// If context was cancelled during the run above, exit the loop
			// now rather than sleeping — export and DB close happen via defer.
			if ctx.Err() != nil {
				log.Println("shutdown: exiting run loop")
				return
			}

			log.Printf("sleeping %s until next cycle", cfg.Validation.RevalidateDelay)
			select {
			case <-ctx.Done():
				log.Println("shutdown: sleep interrupted — exiting cleanly")
				return
			case <-time.After(cfg.Validation.RevalidateDelay):
			}
		}

	// ------------------------------------------------------------------
	default:
		log.Fatalf("unknown mode %q — use check, run, or stats", *mode)
	}
}

// runCheck adds the supplied domains to the store (skipping fresh-active ones),
// then validates every UNKNOWN/STALE entry using the worker pool.
// Always calls ExportLists at the end — even when ctx was cancelled mid-batch,
// so the output files reflect everything that was completed before the signal.
func runCheck(ctx context.Context, cfg *Config, store *Store, resolver *Resolver, rdap *RDAPClient, topn *TopN, domains []string, verbose bool, batch int) {
	if len(domains) > 0 {
		filtered, err := store.FilterNewOrStale(domains, cfg.Validation.StaleTTL)
		if err != nil {
			log.Printf("filter domains: %v", err)
			filtered = domains
		}
		skipped := len(domains) - len(filtered)
		if skipped > 0 {
			log.Printf("skipped %d domain(s) already active and fresh in repository", skipped)
		}
		if len(filtered) > 0 {
			added, err := store.AddDomains(filtered)
			if err != nil {
				log.Printf("add domains: %v", err)
			}
			if added > 0 {
				log.Printf("added %d new domain(s) to repository", added)
			}
		}
	}

	v := NewValidator(cfg, store, resolver, rdap, topn, verbose)
	results := v.RunBatch(ctx, batch)
	switch {
	case results == 0:
		log.Println("nothing to validate — store is fully up-to-date")
	case ctx.Err() != nil:
		log.Printf("validated %d domain(s) before shutdown — exporting partial results", results)
	default:
		log.Printf("validated %d domain(s)", results)
	}
	// Export always runs — partial results from an interrupted batch are still
	// valid and should be reflected in the output files immediately.
	ExportLists(cfg, store)
}

// runStaleRevalidation validates STALE/UNKNOWN entries without a new input list.
func runStaleRevalidation(ctx context.Context, cfg *Config, store *Store, resolver *Resolver, rdap *RDAPClient, topn *TopN, verbose bool, batch int) {
	v := NewValidator(cfg, store, resolver, rdap, topn, verbose)
	results := v.RunBatch(ctx, batch)
	if results > 0 {
		log.Printf("revalidated %d domain(s)", results)
	}
	ExportLists(cfg, store)
}

// doReset removes the SQLite database file (including the WAL and SHM
// sidecar files SQLite may have created) and clears the output directory.
// Called before the store is opened so there is no live handle to the DB yet.
func doReset(cfg *Config) {
	log.Println("reset: wiping database and output directory")

	// Remove the SQLite database and its WAL/SHM sidecars.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := cfg.DB.Path + suffix
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Fatalf("reset: remove %s: %v", path, err)
		}
	}
	log.Printf("reset: removed database %s", cfg.DB.Path)

	// Remove the output directory so stale text files are gone.
	if cfg.Output.Dir != "" {
		if err := os.RemoveAll(cfg.Output.Dir); err != nil && !os.IsNotExist(err) {
			log.Fatalf("reset: remove output dir %s: %v", cfg.Output.Dir, err)
		}
		log.Printf("reset: cleared output directory %s", cfg.Output.Dir)
	}
}

// runStats prints per-status counts from the repository.
func runStats(store *Store) {
	stats, err := store.Stats()
	if err != nil {
		log.Fatalf("stats: %v", err)
	}
	fmt.Println("dns-good repository statistics")
	fmt.Println("-------------------------------")
	total := int64(0)
	for _, status := range []string{"ACTIVE", "INACTIVE", "STALE", "UNKNOWN"} {
		n := stats[status]
		fmt.Printf("  %-10s %d\n", status, n)
		total += n
	}
	fmt.Printf("  %-10s %d\n", "TOTAL", total)
}

// loadDomains reads one domain per line from path (or stdin if path is "").
// Lines starting with '#' and blank lines are ignored.
func loadDomains(path string) []string {
	var r *os.File
	if path == "" {
		// No file given — check if stdin has data piped to it (non-interactive).
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil // interactive terminal with nothing piped
		}
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			log.Fatalf("open input %q: %v", path, err)
		}
		defer f.Close()
		r = f
	}

	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, strings.ToLower(line))
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("read input: %v", err)
	}
	return domains
}

