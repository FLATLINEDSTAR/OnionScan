// Package correlation is the project's core differentiator (see
// docs/ROADMAP.md Phase 3): turning independent pieces of Evidence into
// high-confidence relationship Findings, both within a single scan and
// across different scanned targets (the cross-target evidence graph).
package correlation

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

// DefaultWeights defines baseline independence weights for corroborating evidence types.
var DefaultWeights = map[model.EvidenceType]float64{
	model.EvidenceIP:          0.40,
	model.EvidenceFingerprint: 0.50,
	model.EvidenceTLS:         0.60,
	model.EvidenceHostname:    0.50,
	model.EvidenceExternalRes: 0.35,
	model.EvidenceEmail:       0.30,
	model.EvidenceMetadata:    0.30,
}

// EvidenceWeight returns the independence weight for an evidence type.
func EvidenceWeight(t model.EvidenceType) float64 {
	if w, ok := DefaultWeights[t]; ok {
		return w
	}
	return 0.25
}

// WeightedConfidence calculates the combined confidence from multiple independent evidence pieces:
//
//	C = 1 - \prod_{i=1}^n (1 - w_i)
//
// The result is rounded to 2 decimal places and bounded in [0.0, 0.99].
func WeightedConfidence(weights []float64) float64 {
	if len(weights) == 0 {
		return 0.0
	}
	product := 1.0
	for _, w := range weights {
		if w <= 0.0 {
			continue
		}
		if w >= 1.0 {
			w = 0.99
		}
		product *= (1.0 - w)
	}
	conf := 1.0 - product
	if conf > 0.99 {
		conf = 0.99
	}
	if conf < 0.0 {
		conf = 0.0
	}
	return math.Round(conf*100) / 100
}

// StoreReader is queried by correlation to find historical co-occurrences of evidence across targets.
type StoreReader interface {
	FindCoOccurringTargets(evType model.EvidenceType, rawVal string) ([]storage.TargetLink, error)
}

// Correlate performs same-scan aggregation (retaining backwards compatibility).
func Correlate(target model.Target, findings []model.Finding) []model.Finding {
	return CorrelateWithStore(target, findings, nil)
}

// CorrelateWithStore inspects findings from the current scan, performs same-scan
// correlation using a weighted confidence model, and checks newly-collected evidence
// against the persistent store for cross-target correlation.
func CorrelateWithStore(target model.Target, findings []model.Finding, store StoreReader) []model.Finding {
	hasIP := false
	hasFingerprint := false
	var ipEvidence []model.Evidence
	corroboratingTypes := make(map[model.EvidenceType]bool)

	for _, f := range findings {
		for _, e := range f.Evidence {
			switch e.Type {
			case model.EvidenceIP:
				hasIP = true
				ipEvidence = append(ipEvidence, e)
			case model.EvidenceFingerprint:
				hasFingerprint = true
				corroboratingTypes[e.Type] = true
			case model.EvidenceTLS, model.EvidenceHostname:
				corroboratingTypes[e.Type] = true
			}
		}
	}

	// 1. Same-scan correlation: IP + Fingerprint co-occurrence (INFRA-002)
	// Confidence scales with the number and independence of corroborating evidence types.
	if hasIP && hasFingerprint {
		weights := []float64{EvidenceWeight(model.EvidenceIP)}
		for t := range corroboratingTypes {
			weights = append(weights, EvidenceWeight(t))
		}
		confidence := WeightedConfidence(weights)

		findings = append(findings, model.Finding{
			ID:             "INFRA-002",
			Title:          "Possible origin infrastructure disclosure (correlated)",
			Severity:       model.SeverityHigh,
			Confidence:     confidence,
			Target:         target.Onion,
			Analyzer:       "correlation",
			Evidence:       ipEvidence,
			Explanation:    "A referenced IP address co-occurred with independent response fingerprints or certificates in the same scan. Corroborating evidence across independent channels raises confidence, but should still be manually verified before treating as a confirmed leak.",
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
		peerTargets := make(map[string]bool)
		sharedTypes := make(map[model.EvidenceType]bool)
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
						peerTargets[p.Onion] = true
						sharedTypes[e.Type] = true
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

			// Weighted confidence for cross-target correlation:
			// Base peer correlation weight (0.50) + weight per shared evidence type + extra weight per peer
			weights := []float64{0.50}
			for t := range sharedTypes {
				weights = append(weights, EvidenceWeight(t))
			}
			if len(peerTargets) > 1 {
				for i := 1; i < len(peerTargets); i++ {
					weights = append(weights, 0.20)
				}
			}
			crossConf := WeightedConfidence(weights)
			if crossConf < 0.75 {
				crossConf = 0.75
			}

			findings = append(findings, model.Finding{
				ID:             "INFRA-004",
				Title:          "Shared infrastructure or identity correlated across multiple targets",
				Severity:       model.SeverityHigh,
				Confidence:     crossConf,
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
