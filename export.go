// File    : export.go
// Version : 1.0.0
// Modified: 2026-04-01 14:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Writes one text file per DomainStatus to a configured output
//          directory after every validation pass. Each file contains one
//          domain per line, sorted alphabetically, with a small header
//          block for context. Writes are atomic (temp file + rename) so
//          readers never see a partial file mid-update.
//
//          Output files:
//            <output_dir>/active.txt
//            <output_dir>/inactive.txt
//            <output_dir>/stale.txt
//            <output_dir>/unknown.txt

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ExportLists writes one text file per status into cfg.Output.Dir.
// Called after every validation batch. Non-fatal: errors are logged but
// do not abort the run.
func ExportLists(cfg *Config, store *Store) {
	if cfg.Output.Dir == "" {
		return
	}
	if err := os.MkdirAll(cfg.Output.Dir, 0o755); err != nil {
		log.Printf("export: create output dir %q: %v", cfg.Output.Dir, err)
		return
	}

	statuses := []DomainStatus{StatusActive, StatusInactive, StatusStale, StatusUnknown}
	for _, status := range statuses {
		if err := exportStatus(cfg, store, status); err != nil {
			log.Printf("export: %s: %v", status, err)
		}
	}
}

// exportStatus fetches all entries for one status and writes them atomically.
func exportStatus(cfg *Config, store *Store, status DomainStatus) error {
	// Fetch all entries for this status.
	entries, err := store.GetByStatus(status, 0)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	// Collect and sort domain names for deterministic, diff-friendly output.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Domain)
	}
	sort.Strings(names)

	filename := strings.ToLower(string(status)) + ".txt"
	destPath := filepath.Join(cfg.Output.Dir, filename)
	tmpPath  := destPath + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	// Header block — makes every file self-describing.
	header := fmt.Sprintf(
		"# dns-good — %s domains\n"+
			"# Generated : %s\n"+
			"# Count     : %d\n"+
			"# Score note: %s\n"+
			"#\n",
		strings.ToUpper(string(status)),
		time.Now().UTC().Format(time.RFC3339),
		len(names),
		scoreNote(status),
	)
	if _, err := fmt.Fprint(f, header); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write header: %w", err)
	}

	for _, name := range names {
		if _, err := fmt.Fprintln(f, name); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("write entry: %w", err)
		}
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	// Atomic replace — readers never see a partial write.
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename to %s: %w", destPath, err)
	}

	log.Printf("export: wrote %d %s domain(s) → %s", len(names), status, destPath)
	return nil
}

// scoreNote returns a one-line explanation of what the status means,
// printed in each file's header for human readers.
func scoreNote(status DomainStatus) string {
	switch status {
	case StatusActive:
		return "score > 0 — at least one source confirmed activity"
	case StatusInactive:
		return "score = 0 — no source confirmed activity on last check"
	case StatusStale:
		return fmt.Sprintf("not checked in > stale_ttl — awaiting revalidation")
	case StatusUnknown:
		return "queued but never checked yet"
	default:
		return ""
	}
}

