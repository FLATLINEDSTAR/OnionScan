package storage

import (
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestStore_SaveAndLatestRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	onion := "testtarget.onion"
	now := time.Date(2026, 9, 12, 8, 30, 0, 0, time.UTC)
	expected := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(-1 * time.Minute),
		EndedAt:   now,
		RiskScore: 42,
		Findings: []model.Finding{
			{
				ID:         "OPSEC-002",
				Title:      "Email address disclosed",
				Severity:   model.SeverityMedium,
				Confidence: 0.9,
				Target:     onion,
				Analyzer:   "opsec",
				CreatedAt:  now,
			},
		},
	}

	path, err := store.Save(expected)
	if err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}
	if path == "" {
		t.Errorf("expected non-empty path from Save")
	}

	latest, ok, err := store.Latest(onion)
	if err != nil {
		t.Fatalf("unexpected latest error: %v", err)
	}
	if !ok {
		t.Fatalf("expected latest scan to be found")
	}

	if latest.Target.Onion != expected.Target.Onion {
		t.Errorf("expected target %s, got %s", expected.Target.Onion, latest.Target.Onion)
	}
	if latest.RiskScore != expected.RiskScore {
		t.Errorf("expected risk score %d, got %d", expected.RiskScore, latest.RiskScore)
	}
	if len(latest.Findings) != len(expected.Findings) {
		t.Fatalf("expected %d findings, got %d", len(expected.Findings), len(latest.Findings))
	}
	if latest.Findings[0].ID != expected.Findings[0].ID {
		t.Errorf("expected finding ID %s, got %s", expected.Findings[0].ID, latest.Findings[0].ID)
	}
	if !latest.EndedAt.Equal(expected.EndedAt) {
		t.Errorf("expected endedAt %v, got %v", expected.EndedAt, latest.EndedAt)
	}
}

func TestStore_HistoryOrdering(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()
	onion := "timeline.onion"

	t1 := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	scans := []model.ScanResult{
		{Target: model.Target{Onion: onion}, EndedAt: t2, RiskScore: 20},
		{Target: model.Target{Onion: onion}, EndedAt: t1, RiskScore: 10},
		{Target: model.Target{Onion: onion}, EndedAt: t3, RiskScore: 30},
	}

	for _, s := range scans {
		if _, err := store.Save(s); err != nil {
			t.Fatalf("failed to save scan with endedAt %v: %v", s.EndedAt, err)
		}
	}

	history, err := store.History(onion)
	if err != nil {
		t.Fatalf("unexpected history error: %v", err)
	}

	if len(history) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(history))
	}

	// History must be ordered oldest first: t1, t2, t3
	if !history[0].EndedAt.Equal(t1) || history[0].RiskScore != 10 {
		t.Errorf("expected first scan to be t1 (score 10), got %+v", history[0])
	}
	if !history[1].EndedAt.Equal(t2) || history[1].RiskScore != 20 {
		t.Errorf("expected second scan to be t2 (score 20), got %+v", history[1])
	}
	if !history[2].EndedAt.Equal(t3) || history[2].RiskScore != 30 {
		t.Errorf("expected third scan to be t3 (score 30), got %+v", history[2])
	}

	latest, ok, err := store.Latest(onion)
	if err != nil {
		t.Fatalf("unexpected latest error: %v", err)
	}
	if !ok {
		t.Fatalf("expected latest scan to be found")
	}
	if !latest.EndedAt.Equal(t3) || latest.RiskScore != 30 {
		t.Errorf("expected latest scan to be t3 (score 30), got %+v", latest)
	}
}

func TestStore_NonExistentTarget(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	latest, ok, err := store.Latest("nonexistent.onion")
	if err != nil {
		t.Fatalf("unexpected error on missing target: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false for missing target, got true with %+v", latest)
	}

	history, err := store.History("nonexistent.onion")
	if err != nil {
		t.Fatalf("unexpected error on missing history: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected empty history for missing target, got %d entries", len(history))
	}
}

func TestStore_EvidenceIndexingAndLookup(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	target1 := "alpha.onion"
	target2 := "beta.onion"
	sharedIP := "198.51.100.42"

	scan1 := model.ScanResult{
		Target:    model.Target{Onion: target1},
		StartedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 12, 10, 1, 0, 0, time.UTC),
		Findings: []model.Finding{
			{
				ID:       "INFRA-001",
				Analyzer: "opsec",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: sharedIP, Source: "http://alpha.onion/about"},
					{Type: model.EvidenceEmail, Description: "admin@sharedcorp.com", Source: "http://alpha.onion/contact"},
					{Type: model.EvidenceCredential, Description: "secret_token_redacted", Source: "http://alpha.onion/config"},
				},
			},
		},
	}

	if _, err := store.Save(scan1); err != nil {
		t.Fatalf("failed to save scan1: %v", err)
	}

	scan2 := model.ScanResult{
		Target:    model.Target{Onion: target2},
		StartedAt: time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 12, 11, 1, 0, 0, time.UTC),
		Findings: []model.Finding{
			{
				ID:       "INFRA-001",
				Analyzer: "opsec",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: sharedIP, Source: "http://beta.onion/api"},
				},
			},
		},
	}

	if _, err := store.Save(scan2); err != nil {
		t.Fatalf("failed to save scan2: %v", err)
	}

	// 1. Query shared IP -> should return both alpha.onion and beta.onion
	links, err := store.FindCoOccurringTargets(model.EvidenceIP, sharedIP)
	if err != nil {
		t.Fatalf("FindCoOccurringTargets failed: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 targets for shared IP, got %d", len(links))
	}

	// 2. Query email -> should only return alpha.onion
	emailLinks, err := store.FindCoOccurringTargets(model.EvidenceEmail, "ADMIN@SharedCorp.COM") // tests canonicalization
	if err != nil {
		t.Fatalf("FindCoOccurringTargets email failed: %v", err)
	}
	if len(emailLinks) != 1 || emailLinks[0].Onion != target1 {
		t.Fatalf("expected 1 target (alpha.onion) for email, got %+v", emailLinks)
	}

	// 3. Query credentials -> must be empty (safety rule)
	credLinks, err := store.FindCoOccurringTargets(model.EvidenceCredential, "secret_token_redacted")
	if err != nil {
		t.Fatalf("unexpected cred query error: %v", err)
	}
	if len(credLinks) != 0 {
		t.Fatalf("expected 0 targets for credentials (safety rule), got %d", len(credLinks))
	}

	// 4. Test Targets() listing
	targets, err := store.Targets()
	if err != nil {
		t.Fatalf("Targets() failed: %v", err)
	}
	if len(targets) != 2 || targets[0] != "alpha.onion" || targets[1] != "beta.onion" {
		t.Fatalf("expected [alpha.onion beta.onion], got %+v", targets)
	}
}

func TestFileStore_SaveAndRetrieve(t *testing.T) {
	tempDir := t.TempDir()
	fs := NewFileStore(tempDir)
	defer fs.Close()

	onion := "filestore.onion"
	res := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: time.Now().Add(-time.Minute),
		EndedAt:   time.Now(),
		RiskScore: 15,
	}

	path, err := fs.Save(res)
	if err != nil {
		t.Fatalf("FileStore.Save failed: %v", err)
	}
	if path == "" {
		t.Errorf("expected non-empty path from Save")
	}

	latest, ok, err := fs.Latest(onion)
	if err != nil || !ok {
		t.Fatalf("FileStore.Latest failed: %v, ok=%v", err, ok)
	}
	if latest.RiskScore != 15 {
		t.Errorf("expected risk score 15, got %d", latest.RiskScore)
	}
}

func TestSQLiteStore_InMemory(t *testing.T) {
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite(:memory:) failed: %v", err)
	}
	defer store.Close()

	onion := "memory.onion"
	res := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: time.Now().Add(-time.Minute),
		EndedAt:   time.Now(),
		RiskScore: 88,
	}

	scanID, err := store.Save(res)
	if err != nil {
		t.Fatalf("Save in memory failed: %v", err)
	}
	if scanID == "" {
		t.Errorf("expected non-empty scanID")
	}

	latest, ok, err := store.Latest(onion)
	if err != nil || !ok {
		t.Fatalf("Latest in memory failed: %v, ok=%v", err, ok)
	}
	if latest.RiskScore != 88 {
		t.Errorf("expected risk score 88, got %d", latest.RiskScore)
	}
}

func TestStore_GetScan(t *testing.T) {
	tempDir := t.TempDir()
	sqliteStore, err := New(tempDir)
	if err != nil {
		t.Fatalf("New sqlite store failed: %v", err)
	}
	defer sqliteStore.Close()

	fileStore := NewFileStore(tempDir + "_file")
	defer fileStore.Close()

	onion := "getscan.onion"
	now := time.Date(2026, 9, 12, 12, 30, 0, 0, time.UTC)
	res := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(-time.Minute),
		EndedAt:   now,
		RiskScore: 77,
	}

	for _, s := range []Store{sqliteStore, fileStore} {
		_, err := s.Save(res)
		if err != nil {
			t.Fatalf("Save failed: %v", err)
		}

		scanID := "20260912T123000Z"
		retrieved, ok, err := s.GetScan(onion, scanID)
		if err != nil {
			t.Fatalf("GetScan failed: %v", err)
		}
		if !ok {
			t.Fatalf("GetScan returned ok=false for existing scan")
		}
		if retrieved.RiskScore != 77 {
			t.Errorf("expected risk score 77, got %d", retrieved.RiskScore)
		}

		_, missingOk, err := s.GetScan(onion, "nonexistent-scan-id")
		if err != nil {
			t.Fatalf("GetScan error on missing scan: %v", err)
		}
		if missingOk {
			t.Errorf("expected missingOk=false for nonexistent scan")
		}
	}
}
