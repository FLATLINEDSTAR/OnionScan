// Package correlation is the project's core differentiator (see
// docs/ROADMAP.md Phase 3): turning independent pieces of Evidence into
// high-confidence relationship Findings, both within a single scan and
// across different scanned targets (the cross-target evidence graph).
package correlation

import (
	"fmt"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

// StoreReader is queried by correlation to find historical co-occurrences of evidence across targets.
type StoreReader interface {
	FindCoOccurringTargets(evType model.EvidenceType, rawVal string) ([]storage.TargetLink, error)
}

// Correlate performs same-scan aggregation (retaining backwards compatibility).
func Correlate(target model.Target, findings []model.Finding) []model.Finding {
	return CorrelateWithStore(target, findings, nil)
}

// CorrelateWithStore inspects findings from the current scan, performs same-scan
// correlation, and checks newly-collected evidence against the persistent store
// for cross-target correlation.
func CorrelateWithStore(target model.Target, findings []model.Finding, store StoreReader) []model.Finding {
	hasIP := false
	hasFingerprint := false
	var ipEvidence []model.Evidence

	for _, f := range findings {
		for _, e := range f.Evidence {
			switch e.Type {
			case model.EvidenceIP:
				hasIP = true
				ipEvidence = append(ipEvidence, e)
			case model.EvidenceFingerprint:
				hasFingerprint = true
			}
		}
	}

	// 1. Same-scan correlation: IP + Fingerprint co-occurrence (INFRA-002)
	if hasIP && hasFingerprint {
		findings = append(findings, model.Finding{
			ID:             "INFRA-002",
			Title:          "Possible origin infrastructure disclosure (correlated)",
			Severity:       model.SeverityHigh,
			Confidence:     0.7,
			Target:         target.Onion,
			Analyzer:       "correlation",
			Evidence:       ipEvidence,
			Explanation:    "A referenced IP address co-occurred with a recorded response fingerprint in the same scan. This raises confidence above a standalone IP mention, but should still be manually verified before treating it as a confirmed leak.",
			Recommendation: "Manually verify whether the referenced address is reachable and serves the same content as this onion service.",
			CreatedAt:      time.Now(),
		})
	}

	// 2. Cross-target correlation (INFRA-004)
	if store != nil {
		type evKey struct {
			evType model.EvidenceType
			val    string
		}
		seenKeys := make(map[evKey]bool)
		var crossEvidence []model.Evidence

		for _, f := range findings {
			// Do not correlate findings that were produced by correlation itself
			if f.Analyzer == "correlation" {
				continue
			}

			for _, e := range f.Evidence {
				// Only correlate high-signal evidence types
				switch e.Type {
				case model.EvidenceIP, model.EvidenceTLS, model.EvidenceFingerprint,
					model.EvidenceEmail, model.EvidenceExternalRes:
				default:
					continue
				}

				k := evKey{evType: e.Type, val: strings.TrimSpace(e.Description)}
				if k.val == "" || seenKeys[k] {
					continue
				}
				seenKeys[k] = true

				peers, err := store.FindCoOccurringTargets(e.Type, e.Description)
				if err != nil || len(peers) == 0 {
					continue
				}

				for _, p := range peers {
					if p.Onion != "" && !strings.EqualFold(p.Onion, target.Onion) {
						desc := fmt.Sprintf("Shared %s (%s) also observed on target %s", e.Type, e.Description, p.Onion)
						crossEvidence = append(crossEvidence, model.Evidence{
							Type:        e.Type,
							Description: desc,
							Source:      "cross-target correlation",
						})
					}
				}
			}
		}

		if len(crossEvidence) > 0 {
			crossEvidence = dedupeEvidence(crossEvidence)
			findings = append(findings, model.Finding{
				ID:             "INFRA-004",
				Title:          "Shared infrastructure or identity correlated across multiple targets",
				Severity:       model.SeverityHigh,
				Confidence:     0.85,
				Target:         target.Onion,
				Analyzer:       "correlation",
				Evidence:       crossEvidence,
				Explanation:    "One or more pieces of evidence (IP addresses, TLS certificates, response fingerprints, contact emails, or tracking identifiers) match evidence previously observed on other onion targets in the evidence store. This indicates that these onion services likely share the same origin host, reverse proxy, or operator.",
				Recommendation: "Investigate whether these onion services are intended to share backend infrastructure. To prevent cross-target deanonymization, isolate infrastructure, certificates, and web application assets per onion service.",
				CreatedAt:      time.Now(),
			})
		}
	}

	return findings
}

func dedupeEvidence(in []model.Evidence) []model.Evidence {
	seen := make(map[string]bool)
	var out []model.Evidence
	for _, ev := range in {
		key := fmt.Sprintf("%s|%s", ev.Type, ev.Description)
		if !seen[key] {
			seen[key] = true
			out = append(out, ev)
		}
	}
	return out
}
