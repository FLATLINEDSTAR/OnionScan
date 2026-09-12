// Package risk turns a list of Findings into a single 0-100 score so users
// get a one-glance sense of exposure. The weighting here is a deliberately
// simple starting point -- see issue "Tune risk scoring weights against
// real-world scans" before relying on this for anything beyond MVP demos.
package risk

import (
	"github.com/AryanXCode646/OnionScan/internal/model"
)

var severityWeight = map[model.Severity]float64{
	model.SeverityInfo:     0,
	model.SeverityLow:      5,
	model.SeverityMedium:   15,
	model.SeverityHigh:     30,
	model.SeverityCritical: 50,
}

var severityRank = map[model.Severity]int{
	model.SeverityCritical: 4,
	model.SeverityHigh:     3,
	model.SeverityMedium:   2,
	model.SeverityLow:      1,
	model.SeverityInfo:     0,
}

type findingKey struct {
	id          string
	title       string
	target      string
	analyzer    string
	explanation string
}

func keyForFinding(f model.Finding) findingKey {
	if f.ID != "" || f.Title != "" {
		return findingKey{
			id:     f.ID,
			title:  f.Title,
			target: f.Target,
		}
	}
	return findingKey{
		target:      f.Target,
		analyzer:    f.Analyzer,
		explanation: f.Explanation,
	}
}

type evidenceKey struct {
	evType      model.EvidenceType
	description string
	source      string
}

type findingAgg struct {
	finding     model.Finding
	evidenceSet map[evidenceKey]bool
}

// DeduplicateFindings consolidates duplicate findings across crawled pages.
// It groups findings by (ID, Title, Target) and merges their evidence,
// retaining the maximum confidence and highest severity observed.
// The earliest CreatedAt timestamp is preserved, and the original encounter
// order is maintained.
func DeduplicateFindings(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return nil
	}

	var orderedKeys []findingKey
	aggMap := make(map[findingKey]*findingAgg)

	for _, f := range findings {
		key := keyForFinding(f)
		agg, exists := aggMap[key]
		if !exists {
			evSet := make(map[evidenceKey]bool)
			var uniqueEv []model.Evidence
			for _, ev := range f.Evidence {
				ek := evidenceKey{evType: ev.Type, description: ev.Description, source: ev.Source}
				if !evSet[ek] {
					evSet[ek] = true
					uniqueEv = append(uniqueEv, ev)
				}
			}

			fCopy := f
			fCopy.Evidence = uniqueEv
			aggMap[key] = &findingAgg{
				finding:     fCopy,
				evidenceSet: evSet,
			}
			orderedKeys = append(orderedKeys, key)
			continue
		}

		// Merge duplicate finding into existing aggregated finding
		// 1. Maximum confidence observed
		if f.Confidence > agg.finding.Confidence {
			agg.finding.Confidence = f.Confidence
		}

		// 2. Highest severity observed
		if severityRank[f.Severity] > severityRank[agg.finding.Severity] {
			agg.finding.Severity = f.Severity
		}

		// 3. Earliest CreatedAt
		if agg.finding.CreatedAt.IsZero() || (!f.CreatedAt.IsZero() && f.CreatedAt.Before(agg.finding.CreatedAt)) {
			agg.finding.CreatedAt = f.CreatedAt
		}

		// 4. Fill explanation / recommendation / analyzer if missing
		if agg.finding.Explanation == "" && f.Explanation != "" {
			agg.finding.Explanation = f.Explanation
		}
		if agg.finding.Recommendation == "" && f.Recommendation != "" {
			agg.finding.Recommendation = f.Recommendation
		}
		if agg.finding.Analyzer == "" && f.Analyzer != "" {
			agg.finding.Analyzer = f.Analyzer
		}

		// 5. Merge evidence items, deduplicating identical (Type, Description, Source)
		for _, ev := range f.Evidence {
			ek := evidenceKey{evType: ev.Type, description: ev.Description, source: ev.Source}
			if !agg.evidenceSet[ek] {
				agg.evidenceSet[ek] = true
				agg.finding.Evidence = append(agg.finding.Evidence, ev)
			}
		}
	}

	result := make([]model.Finding, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		result = append(result, aggMap[key].finding)
	}
	return result
}

// Score computes a bounded 0-100 risk score from a set of findings,
// weighting each by severity and confidence. It calculates the score
// based on unique aggregated findings to prevent multi-page crawl spam
// from inflating the score.
func Score(findings []model.Finding) int {
	deduped := DeduplicateFindings(findings)
	total := 0.0
	for _, f := range deduped {
		w, ok := severityWeight[f.Severity]
		if !ok {
			continue
		}
		total += w * f.Confidence
	}
	if total > 100 {
		total = 100
	}
	return int(total)
}
