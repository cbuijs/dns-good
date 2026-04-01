// File    : scorer.go
// Version : 1.0.0
// Modified: 2026-04-01 12:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Converts raw validation check results into a trust score,
//          a list of confirming sources, and a final DomainStatus.
//          All scoring weights are defined as constants in types.go.
//
//          Score breakdown (max 250):
//            TOP_N          +50   — apex found in Tranco top-N list
//            RDAP           +50   — registry reports domain as active
//            DNS_DELEGATION +50   — NS records exist (zone is delegated)
//            DNS_RESOLUTION +100  — apex resolves to an A or AAAA record
//
//          Status rules:
//            score > 0  → ACTIVE
//            score == 0 → INACTIVE

package main

// Score computes the trust score and status for a ValidationResult.
// It mutates r.Score, r.Status, and r.Sources in-place and returns r
// for convenient chaining.
func Score(r *ValidationResult) *ValidationResult {
	r.Score = 0
	r.Sources = r.Sources[:0] // reset without reallocating

	if r.InTopN {
		r.Score += ScoreTopN
		r.Sources = append(r.Sources, SourceTopN)
	}

	if r.RDAPActive {
		r.Score += ScoreRDAP
		r.Sources = append(r.Sources, SourceRDAP)
	}

	if r.HasNS {
		r.Score += ScoreDNSDelegation
		r.Sources = append(r.Sources, SourceDNSDelegation)
	}

	if r.HasA || r.HasAAAA {
		r.Score += ScoreDNSResolution
		r.Sources = append(r.Sources, SourceDNSResolution)
	}

	if r.Score > 0 {
		r.Status = StatusActive
	} else {
		r.Status = StatusInactive
	}

	return r
}

