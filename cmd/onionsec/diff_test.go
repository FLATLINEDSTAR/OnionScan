package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

func TestRunDiff_MissingArgs(t *testing.T) {
	var buf bytes.Buffer
	err := runDiff([]string{"target.onion"}, &buf)
	if err == nil {
		t.Fatalf("expected error for insufficient args, got nil")
	}
	if !strings.Contains(err.Error(), "usage: onionsec diff") {
		t.Errorf("expected usage error, got: %v", err)
	}
}

func TestRunDiff_MissingScans(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "onionsec.db")
	t.Setenv("ONIONSEC_DATA_DIR", dbPath)

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	var buf bytes.Buffer
	err = runDiff([]string{"missing.onion", "20260912T100000Z", "20260912T110000Z"}, &buf)
	if err == nil {
		t.Fatalf("expected error for missing scan, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}
}

func TestRunDiff_Success(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "onionsec.db")
	t.Setenv("ONIONSEC_DATA_DIR", dbPath)

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	targetOnion := "difftarget.onion"
	t1 := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)

	f1 := model.Finding{
		ID:         "OPSEC-001",
		Title:      "Clearnet resource",
		Severity:   model.SeverityMedium,
		Confidence: 0.8,
		Evidence:   []model.Evidence{{Type: model.EvidenceExternalRes, Description: "http://example.com/asset.js"}},
	}
	f2 := model.Finding{
		ID:         "SEC-001",
		Title:      "Clearnet hostname in cert",
		Severity:   model.SeverityHigh,
		Confidence: 0.95,
		Evidence:   []model.Evidence{{Type: model.EvidenceTLS, Description: "example.com"}},
	}
	f3 := model.Finding{
		ID:         "CRED-001",
		Title:      "Exposed credential",
		Severity:   model.SeverityCritical,
		Confidence: 0.99,
		Evidence:   []model.Evidence{{Type: model.EvidenceCredential, Description: "redacted"}},
	}

	// Scan 1: f1 and f2
	scan1 := model.ScanResult{
		Target:    model.Target{Onion: targetOnion},
		StartedAt: t1.Add(-time.Minute),
		EndedAt:   t1,
		RiskScore: 60,
		Findings:  []model.Finding{f1, f2},
	}
	scanID1, err := store.Save(scan1)
	if err != nil {
		t.Fatalf("Save scan1 failed: %v", err)
	}

	// Scan 2: f2 (modified/more evidence) and f3 (new), f1 removed
	f2Modified := f2
	f2Modified.Severity = model.SeverityCritical
	f2Modified.Evidence = append(f2Modified.Evidence, model.Evidence{Type: model.EvidenceTLS, Description: "extra.example.com"})

	scan2 := model.ScanResult{
		Target:    model.Target{Onion: targetOnion},
		StartedAt: t2.Add(-time.Minute),
		EndedAt:   t2,
		RiskScore: 85,
		Findings:  []model.Finding{f2Modified, f3},
	}
	scanID2, err := store.Save(scan2)
	if err != nil {
		t.Fatalf("Save scan2 failed: %v", err)
	}

	jsonOut := filepath.Join(tempDir, "diff.json")
	mdOut := filepath.Join(tempDir, "diff.md")

	var stdout bytes.Buffer
	args := []string{
		targetOnion,
		scanID1,
		scanID2,
		"--json", jsonOut,
		"--md", mdOut,
	}

	if err := runDiff(args, &stdout); err != nil {
		t.Fatalf("runDiff failed: %v", err)
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "SCAN DIFF REPORT") {
		t.Errorf("expected SCAN DIFF REPORT header, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "[+] NEW FINDINGS") || !strings.Contains(outStr, "CRED-001") {
		t.Errorf("expected CRED-001 in new findings, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "[-] REMOVED / RESOLVED FINDINGS") || !strings.Contains(outStr, "OPSEC-001") {
		t.Errorf("expected OPSEC-001 in removed findings, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "[~] CHANGED FINDINGS") || !strings.Contains(outStr, "SEC-001") {
		t.Errorf("expected SEC-001 in changed findings, got:\n%s", outStr)
	}

	// Verify JSON file
	jsonData, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed to read json output: %v", err)
	}
	if !strings.Contains(string(jsonData), `"score_delta": 25`) {
		t.Errorf("expected score_delta 25 in json, got: %s", string(jsonData))
	}

	// Verify Markdown file
	mdData, err := os.ReadFile(mdOut)
	if err != nil {
		t.Fatalf("failed to read md output: %v", err)
	}
	if !strings.Contains(string(mdData), "# Scan Diff Report") {
		t.Errorf("expected Scan Diff Report header in markdown, got: %s", string(mdData))
	}
}
