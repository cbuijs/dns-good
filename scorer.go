// File    : scorer.go
// Version : 1.1.0
// Modified: 2026-04-01 16:00 UTC
//
// Changes:
//   v1.1.0 - 2026-04-01 - min_active_score replaces hardcoded score > 0 rule;
//                          NS-only (score 50) no longer qualifies as ACTIVE by default
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
//            DNS_RESOLUTION +100  — apex resolves to at least one A or AAAA record
//
//          Both conditions must hold for ACTIVE status:
//            1. score >= minActiveScore (from config, default 100)
//            2. live DNS evidence: HasNS or HasA/AAAA must be true
//
//          Common threshold outcomes (default min_active_score = 100):
//            TOP_N only         (50)  → INACTIVE  no DNS evidence
//            RDAP only          (50)  → INACTIVE  no DNS evidence
//            NS only            (50)  → INACTIVE  below threshold
//            TOP_N + NS        (100)  → ACTIVE
//            RDAP + NS         (100)  → ACTIVE
//            A/AAAA only       (100)  → ACTIVE    resolution alone meets threshold
//            all four          (250)  → ACTIVE    maximum confidence

package main

// Score computes the trust score and status for a ValidationResult.
// minActiveScore is the minimum score required for ACTIVE status (from config).
// It mutates r.Score, r.Status, and r.Sources in-place and returns r
// for convenient chaining.
func Score(r *ValidationResult, minActiveScore int) *ValidationResult {
	r.Score = 0
	r.Sources = r.Sources[:0]

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

	// Both conditions must be true for ACTIVE:
	//   1. score meets the configured minimum threshold
	//   2. at least one DNS check produced evidence (NS or A/AAAA)
	// TOP_N and RDAP alone cannot make a domain ACTIVE — they are
	// backward-looking sources that cannot confirm current liveness.
	hasDNSEvidence := r.HasNS || r.HasA || r.HasAAAA
	if r.Score >= minActiveScore && hasDNSEvidence {
		r.Status = StatusActive
	} else {
		r.Status = StatusInactive
	}

	return r
}

