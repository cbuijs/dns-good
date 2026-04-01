// File    : export.go
// Version : 1.1.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.1.0 - 2026-04-01 - Standardised file header
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Writes one text file per DomainStatus to a configured output
//          directory after every validation pass. Atomic writes.

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

func exportStatus(cfg *Config, store *Store, status DomainStatus) error {
	entries, err := store.GetByStatus(status, 0)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

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

	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename to %s: %w", destPath, err)
	}

	log.Printf("export: wrote %d %s domain(s) → %s", len(names), status, destPath)
	return nil
}

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

