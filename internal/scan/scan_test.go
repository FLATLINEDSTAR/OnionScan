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
			w.Write([]byte("User-agent: *\nDisallow: /admin/\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><h1>Hello Onion</h1></body></html>`))
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
