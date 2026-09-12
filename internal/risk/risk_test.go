package risk

import (
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestScore_Empty(t *testing.T) {
	if got := Score(nil); got != 0 {
		t.Errorf("Score(nil) = %d; want 0", got)
	}
	if got := Score([]model.Finding{}); got != 0 {
		t.Errorf("Score([]) = %d; want 0", got)
	}
}

func TestScore_SingleFinding(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "OPSEC-005",
			Title:      "Server disclosure",
			Severity:   model.SeverityLow, // weight 5
			Confidence: 0.8,
			Target:     "test.onion",
		},
	}
	// 5 * 0.8 = 4
	if got := Score(findings); got != 4 {
		t.Errorf("Score = %d; want 4", got)
	}
}

func TestScore_RepeatedFindingsDoNotInflate(t *testing.T) {
	// Issue #66: If 20 crawled pages all trigger OPSEC-005 (Low, weight 5, confidence 0.95),
	// without deduplication 20 * 5 * 0.95 = 95.
	// With deduplication, score must be int(5 * 0.95) = 4.
	var repeated []model.Finding
	for i := 0; i < 20; i++ {
		repeated = append(repeated, model.Finding{
			ID:         "OPSEC-005",
			Title:      "Server software/version disclosure",
			Severity:   model.SeverityLow,
			Confidence: 0.95,
			Target:     "target.onion",
			Evidence: []model.Evidence{
				{
					Type:        model.EvidenceHTTPHeader,
					Description: "Server: Apache/2.4.41",
					Source:      "http://target.onion/page" + string(rune('0'+i)),
				},
			},
		})
	}

	score := Score(repeated)
	if score != 4 {
		t.Fatalf("Score(repeated 20x) = %d; want 4 (un-inflated)", score)
	}
}

func TestScore_DistinctFindingsAccumulate(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "INFO-001",
			Title:      "Info finding",
			Severity:   model.SeverityInfo, // weight 0
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "OPSEC-001",
			Title:      "Low finding",
			Severity:   model.SeverityLow, // weight 5
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "OPSEC-002",
			Title:      "Medium finding",
			Severity:   model.SeverityMedium, // weight 15
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "INFRA-001",
			Title:      "High finding",
			Severity:   model.SeverityHigh, // weight 30
			Confidence: 1.0,
			Target:     "test.onion",
		},
	}
	// 0 + 5 + 15 + 30 = 50
	if got := Score(findings); got != 50 {
		t.Errorf("Score = %d; want 50", got)
	}
}

func TestScore_CapAt100(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "CRIT-001",
			Title:      "Critical 1",
			Severity:   model.SeverityCritical, // weight 50
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "CRIT-002",
			Title:      "Critical 2",
			Severity:   model.SeverityCritical, // weight 50
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "CRIT-003",
			Title:      "Critical 3",
			Severity:   model.SeverityCritical, // weight 50
			Confidence: 1.0,
			Target:     "test.onion",
		},
	}
	// 50 + 50 + 50 = 150 -> bounded at 100
	if got := Score(findings); got != 100 {
		t.Errorf("Score = %d; want 100", got)
	}
}

func TestDeduplicateFindings_Empty(t *testing.T) {
	if got := DeduplicateFindings(nil); got != nil {
		t.Errorf("DeduplicateFindings(nil) = %v; want nil", got)
	}
	if got := DeduplicateFindings([]model.Finding{}); got != nil {
		t.Errorf("DeduplicateFindings([]) = %v; want nil", got)
	}
}

func TestDeduplicateFindings_MergesEvidenceAndPicksMaxConfidenceAndSeverity(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 12, 5, 0, 0, time.UTC)

	findings := []model.Finding{
		{
			ID:             "OPSEC-005",
			Title:          "Server software/version disclosure",
			Severity:       model.SeverityLow,
			Confidence:     0.70,
			Target:         "example.onion",
			Analyzer:       "headers",
			Explanation:    "Server header exposed",
			Recommendation: "Remove Server header",
			CreatedAt:      t2,
			Evidence: []model.Evidence{
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/"},
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/"}, // duplicate in same finding
			},
		},
		{
			ID:             "OPSEC-005",
			Title:          "Server software/version disclosure",
			Severity:       model.SeverityMedium, // escalated severity
			Confidence:     0.95,                 // higher confidence
			Target:         "example.onion",
			Analyzer:       "headers",
			Explanation:    "Server header exposed",
			Recommendation: "Remove Server header",
			CreatedAt:      t1, // earlier timestamp
			Evidence: []model.Evidence{
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/"},      // duplicate from first finding
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/page2"}, // new evidence
			},
		},
	}

	deduped := DeduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(deduped))
	}

	f := deduped[0]
	if f.Confidence != 0.95 {
		t.Errorf("expected max confidence 0.95, got %f", f.Confidence)
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("expected max severity %s, got %s", model.SeverityMedium, f.Severity)
	}
	if !f.CreatedAt.Equal(t1) {
		t.Errorf("expected earliest CreatedAt %v, got %v", t1, f.CreatedAt)
	}
	if len(f.Evidence) != 2 {
		t.Fatalf("expected 2 unique evidence items, got %d: %+v", len(f.Evidence), f.Evidence)
	}

	sources := map[string]bool{}
	for _, ev := range f.Evidence {
		sources[ev.Source] = true
	}
	if !sources["http://example.onion/"] || !sources["http://example.onion/page2"] {
		t.Errorf("expected evidence from both pages, got %+v", sources)
	}
}

func TestDeduplicateFindings_PreservesOrderAndDistinguishesFindings(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "RULE-001",
			Title:      "First Finding",
			Target:     "site.onion",
			Confidence: 0.5,
		},
		{
			ID:         "RULE-002",
			Title:      "Second Finding",
			Target:     "site.onion",
			Confidence: 0.6,
		},
		{
			ID:         "RULE-001",
			Title:      "First Finding",
			Target:     "site.onion",
			Confidence: 0.8,
		},
		{
			ID:         "RULE-001",
			Title:      "Different Title Sharing Same Rule ID",
			Target:     "site.onion",
			Confidence: 0.9,
		},
		{
			ID:         "RULE-001",
			Title:      "First Finding",
			Target:     "different.onion", // different target
			Confidence: 0.7,
		},
	}

	deduped := DeduplicateFindings(findings)
	if len(deduped) != 4 {
		t.Fatalf("expected 4 deduplicated findings, got %d", len(deduped))
	}

	if deduped[0].ID != "RULE-001" || deduped[0].Title != "First Finding" || deduped[0].Target != "site.onion" {
		t.Errorf("unexpected first finding: %+v", deduped[0])
	}
	if deduped[0].Confidence != 0.8 {
		t.Errorf("expected confidence 0.8 for first finding, got %f", deduped[0].Confidence)
	}

	if deduped[1].ID != "RULE-002" || deduped[1].Title != "Second Finding" {
		t.Errorf("unexpected second finding: %+v", deduped[1])
	}

	if deduped[2].ID != "RULE-001" || deduped[2].Title != "Different Title Sharing Same Rule ID" {
		t.Errorf("unexpected third finding: %+v", deduped[2])
	}

	if deduped[3].ID != "RULE-001" || deduped[3].Target != "different.onion" {
		t.Errorf("unexpected fourth finding: %+v", deduped[3])
	}
}
