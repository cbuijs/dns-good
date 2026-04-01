// File    : scorer.go
// Version : 1.2.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.2.0 - 2026-04-01 - Include HasCNAME as valid DNS evidence for ScoreDNSResolution
//   v1.1.0 - 2026-04-01 - min_active_score replaces hardcoded score > 0 rule;
//                          NS-only (score 50) no longer qualifies as ACTIVE by default
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Converts raw validation check results into a trust score,
//          a list of confirming sources, and a final DomainStatus.

package main

// Score computes the trust score and status for a ValidationResult.
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
	// CNAME implies the domain itself correctly maps somewhere in the DNS architecture
	// and counts as successful DNS resolution evidence.
	if r.HasA || r.HasAAAA || r.HasCNAME {
		r.Score += ScoreDNSResolution
		r.Sources = append(r.Sources, SourceDNSResolution)
	}

	// Both conditions must be true for ACTIVE:
	//   1. score meets the configured minimum threshold
	//   2. at least one DNS check produced evidence (NS, A, AAAA, or CNAME)
	hasDNSEvidence := r.HasNS || r.HasA || r.HasAAAA || r.HasCNAME
	if r.Score >= minActiveScore && hasDNSEvidence {
		r.Status = StatusActive
	} else {
		r.Status = StatusInactive
	}

	return r
}
