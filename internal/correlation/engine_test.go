package correlation

import (
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

func TestCorrelate_IPOnly_NoInfra002(t *testing.T) {
	target := model.Target{Onion: "test.onion"}
	findings := []model.Finding{
		{
			ID:         "INFRA-001",
			Title:      "Possible IP address reference",
			Severity:   model.SeverityMedium,
			Confidence: 0.4,
			Target:     target.Onion,
			Evidence: []model.Evidence{
				{Type: model.EvidenceIP, Description: "93.184.216.34", Source: "http://test.onion/"},
			},
			CreatedAt: time.Now(),
		},
	}

	result := Correlate(target, findings)
	for _, f := range result {
		if f.ID == "INFRA-002" {
			t.Errorf("did not expect INFRA-002 when only IP evidence is present, got %+v", f)
		}
	}
	if len(result) != len(findings) {
		t.Errorf("expected %d findings, got %d", len(findings), len(result))
	}
}

func TestCorrelate_FingerprintOnly_NoInfra002(t *testing.T) {
	target := model.Target{Onion: "test.onion"}
	findings := []model.Finding{
		{
			ID:         "FP-001",
			Title:      "Response fingerprint recorded",
			Severity:   model.SeverityInfo,
			Confidence: 1.0,
			Target:     target.Onion,
			Evidence: []model.Evidence{
				{Type: model.EvidenceFingerprint, Description: "abcdef1234567890", Source: "http://test.onion/"},
			},
			CreatedAt: time.Now(),
		},
	}

	result := Correlate(target, findings)
	for _, f := range result {
		if f.ID == "INFRA-002" {
			t.Errorf("did not expect INFRA-002 when only fingerprint evidence is present, got %+v", f)
		}
	}
	if len(result) != len(findings) {
		t.Errorf("expected %d findings, got %d", len(findings), len(result))
	}
}

func TestCorrelate_IPAndFingerprint_EmitsInfra002(t *testing.T) {
	target := model.Target{Onion: "test.onion"}
	ipEv := model.Evidence{Type: model.EvidenceIP, Description: "93.184.216.34", Source: "http://test.onion/"}
	fpEv := model.Evidence{Type: model.EvidenceFingerprint, Description: "abcdef1234567890", Source: "http://test.onion/"}

	findings := []model.Finding{
		{
			ID:         "INFRA-001",
			Title:      "Possible IP address reference",
			Severity:   model.SeverityMedium,
			Confidence: 0.4,
			Target:     target.Onion,
			Evidence:   []model.Evidence{ipEv},
			CreatedAt:  time.Now(),
		},
		{
			ID:         "FP-001",
			Title:      "Response fingerprint recorded",
			Severity:   model.SeverityInfo,
			Confidence: 1.0,
			Target:     target.Onion,
			Evidence:   []model.Evidence{fpEv},
			CreatedAt:  time.Now(),
		},
	}

	result := Correlate(target, findings)

	var found bool
	for _, f := range result {
		if f.ID == "INFRA-002" {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Errorf("expected SeverityHigh for INFRA-002, got %v", f.Severity)
			}
			if f.Confidence != 0.7 {
				t.Errorf("expected confidence 0.7 for INFRA-002, got %f", f.Confidence)
			}
			if f.Analyzer != "correlation" {
				t.Errorf("expected analyzer 'correlation', got %s", f.Analyzer)
			}
			if len(f.Evidence) != 1 || f.Evidence[0].Description != "93.184.216.34" {
				t.Errorf("expected IP evidence attached to INFRA-002, got %+v", f.Evidence)
			}
		}
	}

	if !found {
		t.Errorf("expected INFRA-002 finding when both IP and fingerprint evidence are present")
	}
	if len(result) != len(findings)+1 {
		t.Errorf("expected %d findings, got %d", len(findings)+1, len(result))
	}
}

type mockStore struct {
	links map[string][]storage.TargetLink
}

func (m *mockStore) FindCoOccurringTargets(evType model.EvidenceType, rawVal string) ([]storage.TargetLink, error) {
	key := string(evType) + ":" + rawVal
	return m.links[key], nil
}

func TestCorrelateWithStore_CrossTargetMatches_EmitsInfra004(t *testing.T) {
	target := model.Target{Onion: "service-alpha.onion"}
	findings := []model.Finding{
		{
			ID:       "INFRA-001",
			Analyzer: "opsec",
			Evidence: []model.Evidence{
				{Type: model.EvidenceIP, Description: "203.0.113.5", Source: "http://service-alpha.onion/"},
			},
		},
	}

	store := &mockStore{
		links: map[string][]storage.TargetLink{
			"ip:203.0.113.5": {
				{Onion: "service-alpha.onion"},
				{Onion: "service-beta.onion"},
			},
		},
	}

	result := CorrelateWithStore(target, findings, store)

	var infra004 *model.Finding
	for i := range result {
		if result[i].ID == "INFRA-004" {
			infra004 = &result[i]
			break
		}
	}

	if infra004 == nil {
		t.Fatalf("expected INFRA-004 finding from cross-target correlation, none found")
	}

	if infra004.Severity != model.SeverityHigh {
		t.Errorf("expected SeverityHigh for INFRA-004, got %s", infra004.Severity)
	}

	foundPeer := false
	for _, ev := range infra004.Evidence {
		if ev.Type == model.EvidenceIP && strings.Contains(ev.Description, "service-beta.onion") {
			foundPeer = true
			break
		}
	}
	if !foundPeer {
		t.Errorf("expected peer target service-beta.onion in INFRA-004 evidence, got %+v", infra004.Evidence)
	}
}

func TestCorrelateWithStore_NoPeerMatches_NoInfra004(t *testing.T) {
	target := model.Target{Onion: "service-alpha.onion"}
	findings := []model.Finding{
		{
			ID:       "INFRA-001",
			Analyzer: "opsec",
			Evidence: []model.Evidence{
				{Type: model.EvidenceIP, Description: "203.0.113.5", Source: "http://service-alpha.onion/"},
			},
		},
	}

	// Store only knows about service-alpha.onion (self), no peers
	store := &mockStore{
		links: map[string][]storage.TargetLink{
			"ip:203.0.113.5": {
				{Onion: "service-alpha.onion"},
			},
		},
	}

	result := CorrelateWithStore(target, findings, store)
	for _, f := range result {
		if f.ID == "INFRA-004" {
			t.Errorf("did not expect INFRA-004 when only self target matches")
		}
	}
}

func TestWeightedConfidence(t *testing.T) {
	tests := []struct {
		name     string
		weights  []float64
		expected float64
	}{
		{"empty", nil, 0.0},
		{"single IP", []float64{0.40}, 0.40},
		{"IP and Fingerprint", []float64{0.40, 0.50}, 0.70},
		{"IP, Fingerprint, and TLS", []float64{0.40, 0.50, 0.60}, 0.88},
		{"High corroboration", []float64{0.40, 0.50, 0.60, 0.50}, 0.94},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WeightedConfidence(tt.weights)
			if got != tt.expected {
				t.Errorf("WeightedConfidence(%v) = %f, want %f", tt.weights, got, tt.expected)
			}
		})
	}
}

func TestCorrelate_WeightedConfidenceScaling(t *testing.T) {
	target := model.Target{Onion: "test.onion"}
	ipEv := model.Evidence{Type: model.EvidenceIP, Description: "93.184.216.34", Source: "http://test.onion/"}
	fpEv := model.Evidence{Type: model.EvidenceFingerprint, Description: "abcdef1234567890", Source: "http://test.onion/"}
	tlsEv := model.Evidence{Type: model.EvidenceTLS, Description: "cert-hash-12345", Source: "http://test.onion/"}

	findingsBase := []model.Finding{
		{ID: "INFRA-001", Analyzer: "opsec", Evidence: []model.Evidence{ipEv}},
		{ID: "FP-001", Analyzer: "fingerprint", Evidence: []model.Evidence{fpEv}},
	}

	resBase := Correlate(target, findingsBase)
	var confBase float64
	for _, f := range resBase {
		if f.ID == "INFRA-002" {
			confBase = f.Confidence
		}
	}
	if confBase != 0.70 {
		t.Fatalf("expected baseline confidence 0.70, got %f", confBase)
	}

	// Add corroborating TLS evidence
	findingsWithTLS := append(findingsBase, model.Finding{
		ID:       "SEC-001",
		Analyzer: "tls",
		Evidence: []model.Evidence{tlsEv},
	})

	resWithTLS := Correlate(target, findingsWithTLS)
	var confWithTLS float64
	for _, f := range resWithTLS {
		if f.ID == "INFRA-002" {
			confWithTLS = f.Confidence
		}
	}

	if confWithTLS <= confBase {
		t.Errorf("expected corroborating TLS evidence to increase confidence (%f <= %f)", confWithTLS, confBase)
	}
	if confWithTLS != 0.88 {
		t.Errorf("expected confidence 0.88 with IP+FP+TLS, got %f", confWithTLS)
	}
}
