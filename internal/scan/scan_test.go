package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/analyzer"
	"github.com/AryanXCode646/OnionScan/internal/crawler"
	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

func TestNewRegistryWithClient_WiresAnalyzers(t *testing.T) {
	var dialerInvoked bool
	customTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialerInvoked = true
			return nil, net.ErrClosed
		},
	}
	client := &http.Client{
		Transport: customTransport,
	}

	reg := NewRegistryWithClient(client)
	if len(reg.All()) != 10 {
		t.Errorf("expected 10 analyzers registered, got %d", len(reg.All()))
	}

	// Verify tls analyzer uses the dialer
	var tlsAnalyzer analyzer.Analyzer
	for _, a := range reg.All() {
		if a.Name() == "tls" {
			tlsAnalyzer = a
			break
		}
	}

	if tlsAnalyzer == nil {
		t.Fatalf("tls analyzer not found in registry")
	}

	target := model.Target{Onion: "testsite.onion"}
	page := model.Page{URL: "http://testsite.onion/"}
	_, _ = tlsAnalyzer.Analyze(context.Background(), target, page)

	if !dialerInvoked {
		t.Errorf("expected tls analyzer to invoke custom dialContext")
	}
}

func TestRun_WiresClientToAnalyzers(t *testing.T) {
	var robotsRequested bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			robotsRequested = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Hello Onion</h1></body></html>`))
	}))
	defer ts.Close()

	client := ts.Client()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	defer store.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	target := model.Target{Onion: host}
	limits := crawler.DefaultLimits
	limits.MaxPages = 2

	result, err := Run(context.Background(), client, store, target, limits)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.PagesSeen == 0 {
		t.Errorf("expected crawler to see pages, got 0")
	}

	if !robotsRequested {
		t.Errorf("expected robots analyzer to fetch robots.txt using injected client")
	}

	history, err := store.History(host)
	if err != nil {
		t.Fatalf("store.History failed: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("expected scan result to be saved in store, got %d", len(history))
	}
}

func TestDeduplicateFindings(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "TEST-001",
			Title:      "Test finding",
			Severity:   model.SeverityLow,
			Confidence: 0.5,
			Target:     "test.onion",
			Evidence: []model.Evidence{
				{Type: model.EvidenceHTTPHeader, Description: "Desc 1", Source: "http://test.onion/1"},
			},
		},
		{
			ID:         "TEST-001",
			Title:      "Test finding",
			Severity:   model.SeverityHigh,
			Confidence: 0.9,
			Target:     "test.onion",
			Evidence: []model.Evidence{
				{Type: model.EvidenceHTTPHeader, Description: "Desc 1", Source: "http://test.onion/1"},
				{Type: model.EvidenceHTTPHeader, Description: "Desc 2", Source: "http://test.onion/2"},
			},
		},
	}

	deduped := DeduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(deduped))
	}
	if deduped[0].Severity != model.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", deduped[0].Severity)
	}
	if deduped[0].Confidence != 0.9 {
		t.Errorf("expected confidence 0.9, got %f", deduped[0].Confidence)
	}
	if len(deduped[0].Evidence) != 2 {
		t.Errorf("expected 2 merged evidence items, got %d", len(deduped[0].Evidence))
	}
}

func TestRun_DeduplicatesFindingsAcrossPages(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><body><a href="/page1">P1</a><a href="/page2">P2</a></body></html>`))
		case "/page1":
			_, _ = w.Write([]byte(`<html><body><a href="/page2">P2</a></body></html>`))
		case "/page2":
			_, _ = w.Write([]byte(`<html><body><h1>Done</h1></body></html>`))
		default:
			_, _ = w.Write([]byte(`<html><body></body></html>`))
		}
	}))
	defer ts.Close()

	client := ts.Client()
	host := strings.TrimPrefix(ts.URL, "http://")
	target := model.Target{Onion: host}
	limits := crawler.DefaultLimits
	limits.MaxPages = 5

	result, err := Run(context.Background(), client, nil, target, limits)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.PagesSeen < 3 {
		t.Fatalf("expected at least 3 pages seen, got %d", result.PagesSeen)
	}

	// Count occurrences of OPSEC-005 in result.Findings
	var opsec005Count int
	var opsec005Finding model.Finding
	for _, f := range result.Findings {
		if f.ID == "OPSEC-005" {
			opsec005Count++
			opsec005Finding = f
		}
	}

	if opsec005Count != 1 {
		t.Fatalf("expected OPSEC-005 finding to be deduplicated to 1, got %d", opsec005Count)
	}

	// Verify evidence merged across multiple pages
	if len(opsec005Finding.Evidence) != result.PagesSeen {
		t.Errorf("expected %d evidence items for OPSEC-005, got %d", result.PagesSeen, len(opsec005Finding.Evidence))
	}

	// Risk score must reflect unique distinct issues, not multiplied by page count
	// OPSEC-005 is Low (weight 5), confidence 0.95 -> 4.
	// OPSEC-006 is Info (weight 0), confidence 1.0 -> 0.
	if result.RiskScore != 4 {
		t.Errorf("expected risk score 4 (un-inflated), got %d", result.RiskScore)
	}
}
