// File    : main.go
// Version : 1.6.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.6.0 - 2026-04-01 - Standardised file header
//   v1.5.0 - 2026-04-01 - Graceful shutdown via context: Ctrl-C finishes in-flight work
//   v1.4.0 - 2026-04-01 - Wire up RootZone; pass it to NewResolver
//   v1.3.0 - 2026-04-01 - Added -db flag to override db.path from config
//   v1.2.0 - 2026-04-01 - Added -reset flag to wipe DB and output dir before a run
//   v1.1.0 - 2026-04-01 - Added -output and -verbose flags; verbose threaded through
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Entry point for dns-good. Parses CLI flags, wires up components,
//          dispatches to run modes.

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
	configPath := flag.String("config",  "config.yaml", "Path to YAML config file")
	mode       := flag.String("mode",    "check",       "Run mode: check | run | stats")
	inputFile  := flag.String("input",   "",            "File with one domain per line (check/run mode)")
	workers    := flag.Int(   "workers",  0,            "Override validation worker count (0 = use config)")
	verbose    := flag.Bool(  "verbose", false,         "Print one progress line per domain")
	outputDir  := flag.String("output",  "",            "Override output directory")
	dbPath     := flag.String("db",      "",            "Override database file path")
	reset      := flag.Bool(  "reset",   false,         "Wipe database and output dir before running")
	batch      := flag.Int(   "batch",    0,            "Max domains to validate per run (0 = unlimited)")

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("signal %s received — finishing in-flight work then exiting cleanly", sig)
		cancel()
		sig = <-sigCh
		log.Printf("second signal %s received — forcing exit now", sig)
		os.Exit(1)
	}()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if *workers > 0 { cfg.Validation.Workers = *workers }
	if *outputDir != "" { cfg.Output.Dir = *outputDir }
	if *dbPath != "" { cfg.DB.Path = *dbPath }

	if *reset {
		doReset(cfg)
	}

	store, err := NewStore(cfg.DB.Path)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer func() {
		log.Println("shutdown: closing database")
		store.Close()
	}()

	rootZone := NewRootZone(cfg)
	if err := rootZone.Ensure(); err != nil {
		log.Printf("rootzone: load failed (%v) — falling back to root servers", err)
	}
	resolver := NewResolver(cfg.DNS.MaxDepth, cfg.DNS.Retries, cfg.DNS.Timeout, rootZone)
	rdap     := NewRDAPClient(cfg)
	topn     := NewTopN(cfg)

	switch *mode {
	case "stats":
		runStats(store)
	case "check":
		domains := loadDomains(*inputFile)
		runCheck(ctx, cfg, store, resolver, rdap, topn, domains, *verbose, *batch)
	case "run":
		domains := loadDomains(*inputFile)
		log.Printf("dns-good running in daemon mode")
		for {
			n, _ := store.MarkStaleEntries(cfg.Validation.StaleTTL)
			if n > 0 {
				log.Printf("marked %d entries as STALE", n)
			}
			if len(domains) > 0 {
				runCheck(ctx, cfg, store, resolver, rdap, topn, domains, *verbose, *batch)
			} else {
				runStaleRevalidation(ctx, cfg, store, resolver, rdap, topn, *verbose, *batch)
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("sleeping %s until next cycle", cfg.Validation.RevalidateDelay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(cfg.Validation.RevalidateDelay):
			}
		}
	default:
		log.Fatalf("unknown mode %q — use check, run, or stats", *mode)
	}
}

func runCheck(ctx context.Context, cfg *Config, store *Store, resolver *Resolver, rdap *RDAPClient, topn *TopN, domains []string, verbose bool, batch int) {
	if len(domains) > 0 {
		filtered, _ := store.FilterNewOrStale(domains, cfg.Validation.StaleTTL)
		skipped := len(domains) - len(filtered)
		if skipped > 0 { log.Printf("skipped %d active domain(s)", skipped) }
		if len(filtered) > 0 {
			added, _ := store.AddDomains(filtered)
			if added > 0 { log.Printf("added %d new domain(s)", added) }
		}
	}
	v := NewValidator(cfg, store, resolver, rdap, topn, verbose)
	results := v.RunBatch(ctx, batch)
	log.Printf("validated %d domain(s)", results)
	ExportLists(cfg, store)
}

func runStaleRevalidation(ctx context.Context, cfg *Config, store *Store, resolver *Resolver, rdap *RDAPClient, topn *TopN, verbose bool, batch int) {
	v := NewValidator(cfg, store, resolver, rdap, topn, verbose)
	results := v.RunBatch(ctx, batch)
	if results > 0 { log.Printf("revalidated %d domain(s)", results) }
	ExportLists(cfg, store)
}

func doReset(cfg *Config) {
	log.Println("reset: wiping database and output directory")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(cfg.DB.Path + suffix)
	}
	if cfg.Output.Dir != "" {
		_ = os.RemoveAll(cfg.Output.Dir)
	}
}

func runStats(store *Store) {
	stats, _ := store.Stats()
	fmt.Println("dns-good repository statistics")
	total := int64(0)
	for _, status := range []string{"ACTIVE", "INACTIVE", "STALE", "UNKNOWN"} {
		n := stats[status]
		fmt.Printf("  %-10s %d\n", status, n)
		total += n
	}
	fmt.Printf("  %-10s %d\n", "TOTAL", total)
}

func loadDomains(path string) []string {
	var r *os.File
	if path == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 { return nil }
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil { log.Fatalf("open input %q: %v", path, err) }
		defer f.Close()
		r = f
	}

	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		domains = append(domains, strings.ToLower(line))
	}
	return domains
}

