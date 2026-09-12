package correlation

import (
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
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
