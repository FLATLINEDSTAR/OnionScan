package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func sampleResult() model.ScanResult {
	now := time.Date(2026, 9, 12, 8, 30, 0, 0, time.UTC)
	return model.ScanResult{
		Target:    model.Target{Onion: "example.onion"},
		StartedAt: now.Add(-2 * time.Minute),
		EndedAt:   now,
		PagesSeen: 5,
		RiskScore: 65,
		Findings: []model.Finding{
			{
				ID:             "OPSEC-005",
				Title:          "Server software disclosure",
				Severity:       model.SeverityLow,
				Confidence:     1.0,
				Target:         "example.onion",
				Analyzer:       "headers",
				Explanation:    "Server header leaked version.",
				Recommendation: "Disable server header.",
				Evidence: []model.Evidence{
					{Type: model.EvidenceHTTPHeader, Description: "nginx/1.18.0", Source: "http://example.onion/"},
				},
				CreatedAt: now,
			},
			{
				ID:             "INFRA-002",
				Title:          "Possible origin disclosure",
				Severity:       model.SeverityHigh,
				Confidence:     0.7,
				Target:         "example.onion",
				Analyzer:       "correlation",
				Explanation:    "IP and fingerprint correlated.",
				Recommendation: "Inspect host.",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: "93.184.216.34", Source: "http://example.onion/"},
				},
				CreatedAt: now,
			},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer

	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("unexpected WriteJSON error: %v", err)
	}

	var parsed model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal WriteJSON output: %v", err)
	}

	if parsed.Target.Onion != result.Target.Onion {
		t.Errorf("expected target %s, got %s", result.Target.Onion, parsed.Target.Onion)
	}
	if parsed.RiskScore != result.RiskScore {
		t.Errorf("expected risk score %d, got %d", result.RiskScore, parsed.RiskScore)
	}
	if len(parsed.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(parsed.Findings))
	}
}

func TestWriteMarkdown(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer

	if err := WriteMarkdown(&buf, result); err != nil {
		t.Fatalf("unexpected WriteMarkdown error: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, "# OnionSec report: example.onion") {
		t.Errorf("expected header in markdown, got: %s", out)
	}
	if !strings.Contains(out, "Risk score: **65 / 100**") {
		t.Errorf("expected risk score in markdown, got: %s", out)
	}

	// High severity finding should come before Low severity finding
	highIdx := strings.Index(out, "INFRA-002")
	lowIdx := strings.Index(out, "OPSEC-005")
	if highIdx == -1 || lowIdx == -1 || highIdx > lowIdx {
		t.Errorf("expected INFRA-002 (High) to appear before OPSEC-005 (Low), highIdx=%d, lowIdx=%d", highIdx, lowIdx)
	}

	if !strings.Contains(out, "Evidence:") || !strings.Contains(out, "93.184.216.34") {
		t.Errorf("expected evidence section in markdown, got: %s", out)
	}
}

func TestWriteMarkdown_NoFindings(t *testing.T) {
	result := model.ScanResult{
		Target:    model.Target{Onion: "clean.onion"},
		StartedAt: time.Now(),
		EndedAt:   time.Now(),
		PagesSeen: 1,
		RiskScore: 0,
		Findings:  nil,
	}

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, result); err != nil {
		t.Fatalf("unexpected WriteMarkdown error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No findings.") {
		t.Errorf("expected 'No findings.' message, got: %s", out)
	}
}
