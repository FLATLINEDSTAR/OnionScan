package storage

import (
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestStore_SaveAndLatestRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	store := New(tempDir)

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
	store := New(tempDir)
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
	store := New(tempDir)

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
