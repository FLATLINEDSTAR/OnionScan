package graph

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

func TestBuildGraph_NoHistory(t *testing.T) {
	tempDir := t.TempDir()
	store, err := storage.New(tempDir)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	_, err = BuildGraph("unknown.onion", store)
	if err == nil {
		t.Fatalf("expected error when building graph for target with no history, got nil")
	}
}

func TestBuildGraph_AndRender(t *testing.T) {
	tempDir := t.TempDir()
	store, err := storage.New(tempDir)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	targetA := "service-alpha.onion"
	targetB := "service-beta.onion"
	sharedIP := "198.51.100.42"
	uniqueCert := "cert-sha256-abcdef12345"

	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	// Save scan for target A
	scanA := model.ScanResult{
		Target:    model.Target{Onion: targetA},
		StartedAt: now.Add(-time.Minute),
		EndedAt:   now,
		Findings: []model.Finding{
			{
				ID:       "INFRA-001",
				Analyzer: "opsec",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: sharedIP, Source: "http://" + targetA},
				},
			},
			{
				ID:       "SEC-001",
				Analyzer: "tls",
				Evidence: []model.Evidence{
					{Type: model.EvidenceTLS, Description: uniqueCert, Source: "http://" + targetA},
				},
			},
		},
	}
	if _, err := store.Save(scanA); err != nil {
		t.Fatalf("failed to save scanA: %v", err)
	}

	// Save scan for target B (shares IP with A)
	scanB := model.ScanResult{
		Target:    model.Target{Onion: targetB},
		StartedAt: now.Add(-time.Minute),
		EndedAt:   now,
		Findings: []model.Finding{
			{
				ID:       "INFRA-001",
				Analyzer: "opsec",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: sharedIP, Source: "http://" + targetB},
				},
			},
		},
	}
	if _, err := store.Save(scanB); err != nil {
		t.Fatalf("failed to save scanB: %v", err)
	}

	// Build graph for target A
	g, err := BuildGraph(targetA, store)
	if err != nil {
		t.Fatalf("BuildGraph failed: %v", err)
	}

	if g.Target != targetA {
		t.Errorf("expected target %s, got %s", targetA, g.Target)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("expected 2 evidence nodes, got %d", len(g.Nodes))
	}
	if len(g.Peers) != 1 || g.Peers[0] != targetB {
		t.Errorf("expected peer %s, got %+v", targetB, g.Peers)
	}

	// Test RenderText
	var textBuf bytes.Buffer
	if err := RenderText(&textBuf, g); err != nil {
		t.Fatalf("RenderText failed: %v", err)
	}
	textOutput := textBuf.String()

	if !strings.Contains(textOutput, "target: service-alpha.onion") {
		t.Errorf("text output missing target header: %s", textOutput)
	}
	if !strings.Contains(textOutput, "also seen on service-beta.onion") {
		t.Errorf("text output missing shared peer reference: %s", textOutput)
	}
	if !strings.Contains(textOutput, "unique to target") {
		t.Errorf("text output missing unique to target reference: %s", textOutput)
	}

	// Test RenderDOT
	var dotBuf bytes.Buffer
	if err := RenderDOT(&dotBuf, g); err != nil {
		t.Fatalf("RenderDOT failed: %v", err)
	}
	dotOutput := dotBuf.String()

	if !strings.HasPrefix(dotOutput, "graph G {") {
		t.Errorf("DOT output missing header: %s", dotOutput)
	}
	if !strings.Contains(dotOutput, `"service-alpha.onion" [shape=box`) {
		t.Errorf("DOT output missing target node: %s", dotOutput)
	}
	if !strings.Contains(dotOutput, `"service-beta.onion" [shape=box`) {
		t.Errorf("DOT output missing peer node: %s", dotOutput)
	}
	if !strings.Contains(dotOutput, `shape=ellipse`) {
		t.Errorf("DOT output missing evidence node shape: %s", dotOutput)
	}
}

func TestRenderText_EmptyGraph(t *testing.T) {
	g := &Graph{
		Target: "empty.onion",
	}
	var buf bytes.Buffer
	if err := RenderText(&buf, g); err != nil {
		t.Fatalf("RenderText failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "(no evidence recorded)") {
		t.Errorf("expected empty message, got: %s", out)
	}
}
