package diff

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestDiff_InitialScan(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	newScan := model.ScanResult{
		Target:    model.Target{Onion: "new.onion"},
		EndedAt:   now,
		RiskScore: 35,
		Findings: []model.Finding{
			{ID: "OPSEC-002", Title: "Email disclosed", Severity: model.SeverityMedium},
		},
	}

	d := Diff(model.ScanResult{}, false, newScan)
	if !d.IsInitialScan {
		t.Fatalf("expected IsInitialScan to be true")
	}
	if len(d.NewFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(d.NewFindings))
	}
	if d.NewRiskScore != 35 {
		t.Errorf("expected score 35, got %d", d.NewRiskScore)
	}

	var buf bytes.Buffer
	if err := RenderText(&buf, d); err != nil {
		t.Fatalf("RenderText failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Initial scan recorded") {
		t.Errorf("expected initial scan text, got: %s", out)
	}
}

func TestDiff_IdenticalScans(t *testing.T) {
	t1 := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)

	f1 := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email disclosed",
		Severity:   model.SeverityMedium,
		Confidence: 0.90,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "admin@example.com"}},
	}

	oldScan := model.ScanResult{
		Target:    model.Target{Onion: "same.onion"},
		EndedAt:   t1,
		RiskScore: 20,
		Findings:  []model.Finding{f1},
	}
	newScan := model.ScanResult{
		Target:    model.Target{Onion: "same.onion"},
		EndedAt:   t2,
		RiskScore: 20,
		Findings:  []model.Finding{f1},
	}

	d := Diff(oldScan, true, newScan)
	if d.HasChanges() {
		t.Errorf("expected HasChanges to be false for identical scans")
	}
	if d.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged finding, got %d", d.UnchangedCount)
	}

	var buf bytes.Buffer
	if err := RenderText(&buf, d); err != nil {
		t.Fatalf("RenderText failed: %v", err)
	}
	if !strings.Contains(buf.String(), "No security or infrastructure changes detected") {
		t.Errorf("expected no changes text, got: %s", buf.String())
	}
}

func TestDiff_NewRemovedAndChangedFindings(t *testing.T) {
	t1 := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)

	// Old findings:
	// - OPSEC-004 (will be removed in new scan)
	// - INFRA-001 (will be changed in new scan: new evidence added, confidence shifted)
	fRemoved := model.Finding{ID: "OPSEC-004", Title: "Debug endpoint", Severity: model.SeverityLow}
	fOldInfra := model.Finding{
		ID:         "INFRA-001",
		Title:      "IP address reference",
		Severity:   model.SeverityMedium,
		Confidence: 0.40,
		Evidence:   []model.Evidence{{Type: model.EvidenceIP, Description: "198.51.100.1"}},
	}

	// New findings:
	// - INFRA-001 (modified: new evidence item)
	// - CRED-001 (newly added finding)
	fNewInfra := model.Finding{
		ID:         "INFRA-001",
		Title:      "IP address reference",
		Severity:   model.SeverityHigh, // changed severity
		Confidence: 0.70,               // changed confidence
		Evidence: []model.Evidence{
			{Type: model.EvidenceIP, Description: "198.51.100.1"},
			{Type: model.EvidenceIP, Description: "198.51.100.2"}, // new evidence
		},
	}
	fAdded := model.Finding{ID: "CRED-001", Title: "API key leaked", Severity: model.SeverityHigh}

	oldScan := model.ScanResult{
		Target:    model.Target{Onion: "test.onion"},
		EndedAt:   t1,
		RiskScore: 30,
		Findings:  []model.Finding{fRemoved, fOldInfra},
	}
	newScan := model.ScanResult{
		Target:    model.Target{Onion: "test.onion"},
		EndedAt:   t2,
		RiskScore: 65,
		Findings:  []model.Finding{fNewInfra, fAdded},
	}

	d := Diff(oldScan, true, newScan)
	if !d.HasChanges() {
		t.Fatalf("expected HasChanges to be true")
	}
	if d.ScoreDelta != 35 {
		t.Errorf("expected ScoreDelta 35, got %d", d.ScoreDelta)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].ID != "CRED-001" {
		t.Errorf("expected CRED-001 in NewFindings, got %+v", d.NewFindings)
	}
	if len(d.RemovedFindings) != 1 || d.RemovedFindings[0].ID != "OPSEC-004" {
		t.Errorf("expected OPSEC-004 in RemovedFindings, got %+v", d.RemovedFindings)
	}
	if len(d.ChangedFindings) != 1 || d.ChangedFindings[0].ID != "INFRA-001" {
		t.Fatalf("expected INFRA-001 in ChangedFindings, got %+v", d.ChangedFindings)
	}

	cf := d.ChangedFindings[0]
	changeSummary := strings.Join(cf.Changes, " | ")
	if !strings.Contains(changeSummary, "Severity changed") {
		t.Errorf("expected severity change mentioned, got: %s", changeSummary)
	}
	if !strings.Contains(changeSummary, "Confidence shifted") {
		t.Errorf("expected confidence shift mentioned, got: %s", changeSummary)
	}
	if !strings.Contains(changeSummary, "new evidence items") {
		t.Errorf("expected new evidence items mentioned, got: %s", changeSummary)
	}

	// Verify RenderText
	var textBuf bytes.Buffer
	if err := RenderText(&textBuf, d); err != nil {
		t.Fatalf("RenderText failed: %v", err)
	}
	text := textBuf.String()
	if !strings.Contains(text, "[+] NEW FINDINGS") || !strings.Contains(text, "[-] REMOVED / RESOLVED") || !strings.Contains(text, "[~] CHANGED FINDINGS") {
		t.Errorf("RenderText missing sections: %s", text)
	}

	// Verify RenderMarkdown
	var mdBuf bytes.Buffer
	if err := RenderMarkdown(&mdBuf, d); err != nil {
		t.Fatalf("RenderMarkdown failed: %v", err)
	}
	md := mdBuf.String()
	if !strings.Contains(md, "New Findings") || !strings.Contains(md, "Resolved / Removed Findings") || !strings.Contains(md, "Changed Findings") {
		t.Errorf("RenderMarkdown missing sections: %s", md)
	}

	// Verify RenderJSON
	var jsonBuf bytes.Buffer
	if err := RenderJSON(&jsonBuf, d); err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"score_delta": 35`) {
		t.Errorf("RenderJSON invalid output: %s", jsonBuf.String())
	}
}

func TestDiff_MultipleFindingsSameRuleID(t *testing.T) {
	t1 := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)

	// Scan 1 has 3 distinct findings sharing the same rule ID (OPSEC-002)
	fAlice := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed in page content",
		Severity:   model.SeverityMedium,
		Confidence: 0.90,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "alice@example.com"}},
	}
	fBob := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed in page content",
		Severity:   model.SeverityMedium,
		Confidence: 0.90,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "bob@example.com"}},
	}
	fCharlie := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed in page content",
		Severity:   model.SeverityMedium,
		Confidence: 0.90,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "charlie@example.com"}},
	}

	// Scan 2:
	// - alice and charlie resolved
	// - bob persists
	// - david added (new finding under OPSEC-002)
	fDavid := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed in page content",
		Severity:   model.SeverityMedium,
		Confidence: 0.90,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "david@example.com"}},
	}

	oldScan := model.ScanResult{
		Target:    model.Target{Onion: "multi.onion"},
		EndedAt:   t1,
		RiskScore: 45,
		Findings:  []model.Finding{fAlice, fBob, fCharlie},
	}
	newScan := model.ScanResult{
		Target:    model.Target{Onion: "multi.onion"},
		EndedAt:   t2,
		RiskScore: 30,
		Findings:  []model.Finding{fBob, fDavid},
	}

	d := Diff(oldScan, true, newScan)

	if !d.HasChanges() {
		t.Fatalf("expected HasChanges to be true")
	}

	// New findings: david only
	if len(d.NewFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d: %+v", len(d.NewFindings), d.NewFindings)
	}
	if d.NewFindings[0].Evidence[0].Description != "david@example.com" {
		t.Errorf("expected david@example.com as new finding, got %s", d.NewFindings[0].Evidence[0].Description)
	}

	// Removed findings: alice and charlie
	if len(d.RemovedFindings) != 2 {
		t.Fatalf("expected 2 removed findings, got %d: %+v", len(d.RemovedFindings), d.RemovedFindings)
	}
	removedEmails := map[string]bool{}
	for _, f := range d.RemovedFindings {
		if len(f.Evidence) > 0 {
			removedEmails[f.Evidence[0].Description] = true
		}
	}
	if !removedEmails["alice@example.com"] || !removedEmails["charlie@example.com"] {
		t.Errorf("expected alice and charlie in removed findings, got: %+v", removedEmails)
	}

	// ResolvedFindings should match RemovedFindings
	if len(d.ResolvedFindings) != len(d.RemovedFindings) {
		t.Errorf("expected ResolvedFindings len %d, got %d", len(d.RemovedFindings), len(d.ResolvedFindings))
	}

	// Persisting findings: bob
	if len(d.PersistingFindings) != 1 {
		t.Fatalf("expected 1 persisting finding, got %d", len(d.PersistingFindings))
	}
	if d.PersistingFindings[0].Evidence[0].Description != "bob@example.com" {
		t.Errorf("expected bob@example.com to persist, got %s", d.PersistingFindings[0].Evidence[0].Description)
	}
	if d.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged finding, got %d", d.UnchangedCount)
	}
	if len(d.ChangedFindings) != 0 {
		t.Errorf("expected 0 changed findings, got %d", len(d.ChangedFindings))
	}
}

func TestDiff_MultipleFindingsSameRuleID_WithModifications(t *testing.T) {
	t1 := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)

	f1 := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed",
		Severity:   model.SeverityMedium,
		Confidence: 0.80,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "user1@example.com"}},
	}
	f2 := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed",
		Severity:   model.SeverityMedium,
		Confidence: 0.80,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "user2@example.com"}},
	}

	// In new scan:
	// - f1 is resolved (removed)
	// - f2 modified (severity escalated to High, confidence 0.95)
	// - f3 is newly added
	f2Modified := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed",
		Severity:   model.SeverityHigh,
		Confidence: 0.95,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "user2@example.com"}},
	}
	f3New := model.Finding{
		ID:         "OPSEC-002",
		Title:      "Email address disclosed",
		Severity:   model.SeverityLow,
		Confidence: 0.50,
		Evidence:   []model.Evidence{{Type: model.EvidenceEmail, Description: "user3@example.com"}},
	}

	oldScan := model.ScanResult{
		Target:    model.Target{Onion: "mod.onion"},
		EndedAt:   t1,
		Findings:  []model.Finding{f1, f2},
		RiskScore: 30,
	}
	newScan := model.ScanResult{
		Target:    model.Target{Onion: "mod.onion"},
		EndedAt:   t2,
		Findings:  []model.Finding{f2Modified, f3New},
		RiskScore: 40,
	}

	d := Diff(oldScan, true, newScan)

	if len(d.RemovedFindings) != 1 || d.RemovedFindings[0].Evidence[0].Description != "user1@example.com" {
		t.Errorf("expected user1@example.com in removed findings, got %+v", d.RemovedFindings)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].Evidence[0].Description != "user3@example.com" {
		t.Errorf("expected user3@example.com in new findings, got %+v", d.NewFindings)
	}
	if len(d.ChangedFindings) != 1 {
		t.Fatalf("expected 1 changed finding, got %d", len(d.ChangedFindings))
	}
	if d.ChangedFindings[0].NewFinding.Evidence[0].Description != "user2@example.com" {
		t.Errorf("expected user2@example.com in changed findings, got %+v", d.ChangedFindings[0])
	}
	if d.UnchangedCount != 0 {
		t.Errorf("expected unchanged count 0, got %d", d.UnchangedCount)
	}
}

func TestDiff_MultipleFindingsWithoutEvidence(t *testing.T) {
	t1 := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)

	// Findings with same ID but different explanations/titles and no evidence
	f1 := model.Finding{
		ID:          "OPSEC-004",
		Title:       "Debug endpoint exposed",
		Explanation: "Exposed /debug/pprof endpoint",
		Severity:    model.SeverityHigh,
	}
	f2 := model.Finding{
		ID:          "OPSEC-004",
		Title:       "Debug endpoint exposed",
		Explanation: "Exposed /status endpoint",
		Severity:    model.SeverityLow,
	}

	// In scan 2: /debug/pprof was fixed, /status remains, and /metrics added
	f3 := model.Finding{
		ID:          "OPSEC-004",
		Title:       "Debug endpoint exposed",
		Explanation: "Exposed /metrics endpoint",
		Severity:    model.SeverityMedium,
	}

	oldScan := model.ScanResult{
		Target:   model.Target{Onion: "endpoints.onion"},
		EndedAt:  t1,
		Findings: []model.Finding{f1, f2},
	}
	newScan := model.ScanResult{
		Target:   model.Target{Onion: "endpoints.onion"},
		EndedAt:  t2,
		Findings: []model.Finding{f2, f3},
	}

	d := Diff(oldScan, true, newScan)

	if len(d.RemovedFindings) != 1 || d.RemovedFindings[0].Explanation != "Exposed /debug/pprof endpoint" {
		t.Errorf("expected pprof in removed findings, got %+v", d.RemovedFindings)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].Explanation != "Exposed /metrics endpoint" {
		t.Errorf("expected metrics in new findings, got %+v", d.NewFindings)
	}
	if len(d.PersistingFindings) != 1 || d.PersistingFindings[0].Explanation != "Exposed /status endpoint" {
		t.Errorf("expected status in persisting findings, got %+v", d.PersistingFindings)
	}
	if d.UnchangedCount != 1 {
		t.Errorf("expected unchanged count 1, got %d", d.UnchangedCount)
	}
}
