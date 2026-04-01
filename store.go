// File    : store.go
// Version : 1.2.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.2.0 - 2026-04-01 - Standardised file header
//   v1.1.0 - 2026-04-01 - Removed extractApex; moved to apex.go (PSL-backed)
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: SQLite-backed domain repository. Handles all persistence.

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS domains (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain       TEXT     UNIQUE NOT NULL,
    apex         TEXT     NOT NULL DEFAULT '',
    status       TEXT     NOT NULL DEFAULT 'UNKNOWN',
    score        INTEGER  NOT NULL DEFAULT 0,
    first_seen   DATETIME,
    last_active  DATETIME,
    last_checked DATETIME,
    sources      TEXT     NOT NULL DEFAULT '[]',
    raw_data     TEXT     NOT NULL DEFAULT '{}',
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at   DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_status        ON domains(status);
CREATE INDEX IF NOT EXISTS idx_last_checked  ON domains(last_checked);
CREATE INDEX IF NOT EXISTS idx_apex          ON domains(apex);
`

type Store struct {
	db *sql.DB
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000")
	if err != nil { return nil, fmt.Errorf("open db %q: %w", path, err) }
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Upsert(r *ValidationResult) error {
	sources, _ := json.Marshal(r.Sources)
	rawData, _ := json.Marshal(r)

	var lastActive interface{} = nil
	if r.Status == StatusActive { lastActive = r.CheckedAt }

	_, err := s.db.Exec(`
		INSERT INTO domains
			(domain, apex, status, score, first_seen, last_active, last_checked, sources, raw_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			apex         = excluded.apex,
			status       = excluded.status,
			score        = excluded.score,
			first_seen   = COALESCE(first_seen, excluded.first_seen),
			last_active  = CASE WHEN excluded.last_active IS NOT NULL THEN excluded.last_active ELSE last_active END,
			last_checked = excluded.last_checked,
			sources      = excluded.sources,
			raw_data     = excluded.raw_data,
			updated_at   = datetime('now')
	`, r.Domain, r.Apex, string(r.Status), r.Score, r.CheckedAt, lastActive, r.CheckedAt, string(sources), string(rawData))
	return err
}

func (s *Store) AddDomains(domains []string) (added int, err error) {
	tx, err := s.db.Begin()
	if err != nil { return 0, err }
	defer func() { if err != nil { tx.Rollback() } }()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO domains (domain, apex, status, sources, raw_data) VALUES (?, ?, 'UNKNOWN', '[]', '{}')`)
	if err != nil { return 0, err }
	defer stmt.Close()

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" { continue }
		res, err2 := stmt.Exec(d, extractApex(d))
		if err2 != nil { err = err2; return added, err }
		n, _ := res.RowsAffected()
		added += int(n)
	}
	return added, tx.Commit()
}

func (s *Store) GetNeedingValidation(limit int) ([]*DomainEntry, error) {
	q := `SELECT id, domain, apex, status, score, first_seen, last_active, last_checked, sources FROM domains WHERE status IN ('UNKNOWN', 'STALE') ORDER BY last_checked ASC NULLS FIRST`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = s.db.Query(q+" LIMIT ?", limit)
	} else {
		rows, err = s.db.Query(q)
	}
	if err != nil { return nil, err }
	defer rows.Close()
	return scanEntries(rows)
}

func (s *Store) MarkStaleEntries(staleTTL time.Duration) (int64, error) {
	cutoff := time.Now().Add(-staleTTL)
	res, err := s.db.Exec(`UPDATE domains SET status = 'STALE', updated_at = datetime('now') WHERE status IN ('ACTIVE', 'INACTIVE') AND (last_checked IS NULL OR last_checked < ?)`, cutoff)
	if err != nil { return 0, err }
	return res.RowsAffected()
}

func (s *Store) Stats() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM domains GROUP BY status`)
	if err != nil { return nil, err }
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var st string
		var n int64
		if err := rows.Scan(&st, &n); err != nil { return nil, err }
		out[st] = n
	}
	return out, rows.Err()
}

func (s *Store) FilterNewOrStale(domains []string, staleTTL time.Duration) ([]string, error) {
	if len(domains) == 0 { return nil, nil }
	cutoff := time.Now().Add(-staleTTL)
	
	normalised := make([]string, 0, len(domains))
	seen := make(map[string]bool, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] { continue }
		seen[d] = true
		normalised = append(normalised, d)
	}

	const chunkSize = 500
	freshActive := make(map[string]bool)

	for i := 0; i < len(normalised); i += chunkSize {
		end := i + chunkSize
		if end > len(normalised) { end = len(normalised) }
		chunk := normalised[i:end]

		placeholders := strings.Repeat("?,", len(chunk))
		placeholders = placeholders[:len(placeholders)-1]

		args := make([]any, 0, len(chunk)+1)
		for _, d := range chunk { args = append(args, d) }
		args = append(args, cutoff)

		rows, err := s.db.Query(fmt.Sprintf(`SELECT domain FROM domains WHERE domain IN (%s) AND status = 'ACTIVE' AND last_checked >= ?`, placeholders), args...)
		if err != nil { return nil, fmt.Errorf("filter query: %w", err) }
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil { rows.Close(); return nil, err }
			freshActive[d] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil { return nil, err }
	}

	out := make([]string, 0, len(normalised))
	for _, d := range normalised {
		if !freshActive[d] { out = append(out, d) }
	}
	return out, nil
}

func (s *Store) GetAll(limit, offset int) ([]*DomainEntry, error) {
	q := `SELECT id, domain, apex, status, score, first_seen, last_active, last_checked, sources FROM domains ORDER BY score DESC, domain ASC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = s.db.Query(q+" LIMIT ? OFFSET ?", limit, offset)
	} else {
		rows, err = s.db.Query(q)
	}
	if err != nil { return nil, err }
	defer rows.Close()
	return scanEntries(rows)
}

func (s *Store) GetByStatus(status DomainStatus, limit int) ([]*DomainEntry, error) {
	q := `SELECT id, domain, apex, status, score, first_seen, last_active, last_checked, sources FROM domains WHERE status = ? ORDER BY score DESC, last_checked DESC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = s.db.Query(q+" LIMIT ?", string(status), limit)
	} else {
		rows, err = s.db.Query(q, string(status))
	}
	if err != nil { return nil, err }
	defer rows.Close()
	return scanEntries(rows)
}

func scanEntries(rows *sql.Rows) ([]*DomainEntry, error) {
	var out []*DomainEntry
	for rows.Next() {
		e := &DomainEntry{}
		var srcJSON string
		var firstSeen, lastActive, lastChecked sql.NullTime
		if err := rows.Scan(&e.ID, &e.Domain, &e.Apex, &e.Status, &e.Score, &firstSeen, &lastActive, &lastChecked, &srcJSON); err != nil {
			return nil, err
		}
		if firstSeen.Valid   { e.FirstSeen   = firstSeen.Time   }
		if lastActive.Valid  { e.LastActive  = lastActive.Time  }
		if lastChecked.Valid { e.LastChecked = lastChecked.Time }
		_ = json.Unmarshal([]byte(srcJSON), &e.Sources)
		out = append(out, e)
	}
	return out, rows.Err()
}

