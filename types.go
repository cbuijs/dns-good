// File    : types.go
// Version : 1.0.0
// Modified: 2026-04-01 12:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Core types, constants, and score weights shared across
//          the entire dns-good application. Nothing here does I/O.

package main

import "time"

// DomainStatus represents the lifecycle state of a domain in the repository.
type DomainStatus string

const (
	// StatusActive — recently validated with at least one source confirming existence.
	StatusActive DomainStatus = "ACTIVE"

	// StatusStale — entry is still valid but the check timestamp is older than StaleTTL.
	// The store marks these; the validator picks them up for revalidation.
	StatusStale DomainStatus = "STALE"

	// StatusInactive — last validation returned zero evidence of a live domain.
	// Could be expired, unregistered, or DNS infrastructure fully removed.
	StatusInactive DomainStatus = "INACTIVE"

	// StatusUnknown — domain is queued in the repository but has never been checked.
	StatusUnknown DomainStatus = "UNKNOWN"
)

// ValidationSource identifies which check contributed to a domain's score.
type ValidationSource string

const (
	SourceTopN          ValidationSource = "TOP_N"          // Seen in Tranco/Umbrella top-N list
	SourceRDAP          ValidationSource = "RDAP"           // RDAP confirms active registration
	SourceDNSDelegation ValidationSource = "DNS_DELEGATION" // NS records exist (zone is delegated)
	SourceDNSResolution ValidationSource = "DNS_RESOLUTION" // A or AAAA records resolve for the apex
)

// Score weights per source. Max attainable is ScoreMax (250).
// Weights match the spec exactly:
//   TOP_N          50  — presence in a well-known popularity list
//   RDAP           50  — registry confirms active registration
//   DNS_DELEGATION 50  — zone is delegated (NS records exist)
//   DNS_RESOLUTION 100 — apex actually resolves to an IP (A or AAAA)
const (
	ScoreTopN          = 50
	ScoreRDAP          = 50
	ScoreDNSDelegation = 50
	ScoreDNSResolution = 100
	ScoreMax           = 250 // sum of all four weights
)

// DomainEntry is the persistent record stored in the SQLite repository.
type DomainEntry struct {
	ID          int64
	Domain      string             // Full name as submitted (may be a subdomain)
	Apex        string             // Registered apex, e.g. "example.com" for "sub.example.com"
	Status      DomainStatus
	Score       int                // 0–250; higher = more sources confirmed activity
	FirstSeen   time.Time          // Timestamp of the very first successful validation
	LastActive  time.Time          // Most recent time the domain had score > 0
	LastChecked time.Time          // Timestamp of the last validation attempt
	Sources     []ValidationSource // Which sources confirmed activity on the last check
	RawData     string             // JSON blob of the last full ValidationResult (for debugging)
}

// ValidationResult holds the complete output of a single validation pass over one domain.
// All individual check outputs are gathered here before being fed to the scorer.
type ValidationResult struct {
	Domain    string
	Apex      string
	CheckedAt time.Time

	// TOP_N check — answered from in-memory map, no network call.
	InTopN   bool
	TopNRank int // 1-based rank; 0 = not in list

	// RDAP / WHOIS check.
	RDAPActive bool
	RDAPStatus string    // Raw status string(s) from the RDAP JSON response
	RDAPExpiry time.Time // Expiry date parsed from RDAP events (zero if unknown)

	// DNS delegation check — NS records for the apex.
	HasNS     bool
	NSRecords []string

	// DNS resolution check — A/AAAA records for the apex.
	HasA    bool
	HasAAAA bool

	// Computed by scorer.go after all checks complete.
	Score   int
	Status  DomainStatus
	Sources []ValidationSource

	// Non-fatal errors from any validator; a domain can partially validate.
	Errors []string
}

