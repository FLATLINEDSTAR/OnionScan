package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/storage"
)

func TestLoadTargets(t *testing.T) {
	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "targets.txt")
	content := `# Fleet targets
http://alpha.onion
https://beta.onion/
# comment line

gamma.onion
`
	if err := os.WriteFile(targetsFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write targets file: %v", err)
	}

	targets, err := loadTargets("single.onion", targetsFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"single.onion", "alpha.onion", "beta.onion", "gamma.onion"}
	if len(targets) != len(expected) {
		t.Fatalf("expected %d targets, got %d: %+v", len(expected), len(targets), targets)
	}
	for i, exp := range expected {
		if targets[i] != exp {
			t.Errorf("expected target[%d]=%s, got %s", i, exp, targets[i])
		}
	}
}

func TestRunMonitor_QuietAndFailOnChanges(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "onionsec.db")
	t.Setenv("ONIONSEC_DATA_DIR", dbPath)

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}
	defer store.Close()

	// 1. Setup local mock server
	var serverHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverHeader != "" {
			w.Header().Set("Server", serverHeader)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Welcome</body></html>`))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	targetHost := u.Host

	// Custom client routing to local mock server
	mockClient := server.Client()

	// 2. First monitor run -> baseline established
	var stdout1, stderr1 bytes.Buffer
	err = runMonitorWithClient(context.Background(), []string{targetHost}, mockClient, &stdout1, &stderr1)
	if err != nil {
		t.Fatalf("initial runMonitor failed: %v", err)
	}
	if !strings.Contains(stdout1.String(), "Initial scan recorded") {
		t.Errorf("expected initial scan text, got: %s", stdout1.String())
	}

	// 3. Second monitor run with --quiet and NO changes -> stdout must be completely silent!
	var stdout2, stderr2 bytes.Buffer
	err = runMonitorWithClient(context.Background(), []string{targetHost, "--quiet", "--fail-on-changes"}, mockClient, &stdout2, &stderr2)
	if err != nil {
		t.Fatalf("second runMonitor with no changes failed: %v", err)
	}
	if stdout2.Len() > 0 {
		t.Errorf("expected empty stdout on quiet run without changes, got: %s", stdout2.String())
	}

	// 4. Change server response (disclosing Apache server header -> creates new finding)
	serverHeader = "Apache/2.4.50"
	var stdout3, stderr3 bytes.Buffer
	err = runMonitorWithClient(context.Background(), []string{targetHost, "--quiet", "--fail-on-changes"}, mockClient, &stdout3, &stderr3)
	if err == nil {
		t.Fatalf("expected exitCodeError on changes detected with --fail-on-changes, got nil")
	}

	var exitErr *exitCodeError
	if !errors.As(err, &exitErr) || exitErr.code != 2 {
		t.Errorf("expected exitCodeError with code 2, got: %v", err)
	}

	// In quiet mode, stdout SHOULD contain report when changes exist!
	if !strings.Contains(stdout3.String(), "[+] NEW FINDINGS") {
		t.Errorf("expected stdout to output new findings when changed, got:\n%s", stdout3.String())
	}
}

func TestRunMonitor_FailAboveScore(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "onionsec.db")
	t.Setenv("ONIONSEC_DATA_DIR", dbPath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>contact: admin@secretcorp.com, ip: 198.51.100.1</body></html>`))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	targetHost := u.Host
	mockClient := server.Client()

	var stdout, stderr bytes.Buffer
	// Threshold set to 0, findings should produce score > 0 and trigger failure
	err := runMonitorWithClient(context.Background(), []string{targetHost, "--fail-above-score", "0"}, mockClient, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected error when score exceeds threshold, got nil")
	}

	var exitErr *exitCodeError
	if !errors.As(err, &exitErr) || exitErr.code != 2 {
		t.Errorf("expected exit code 2, got: %v", err)
	}
}

func TestRunMonitor_IntervalLoop(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "onionsec.db")
	t.Setenv("ONIONSEC_DATA_DIR", dbPath)

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	targetHost := u.Host
	mockClient := server.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := runMonitorWithClient(ctx, []string{targetHost, "--interval", "40ms", "--quiet"}, mockClient, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected graceful termination on context timeout, got: %v", err)
	}

	if calls < 2 {
		t.Errorf("expected recurring monitor to execute multiple cycles (calls >= 2), got %d", calls)
	}
}

func TestRunScan_TargetsFileAndQuiet(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "onionsec.db")
	t.Setenv("ONIONSEC_DATA_DIR", dbPath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Clean page</body></html>`))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	targetsFile := filepath.Join(tempDir, "targets.txt")
	_ = os.WriteFile(targetsFile, []byte(fmt.Sprintf("%s\n", u.Host)), 0o644)

	var stdout, stderr bytes.Buffer
	err := runScanWithClient(context.Background(), []string{"--targets-file", targetsFile, "--quiet"}, server.Client(), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runScanWithClient failed: %v", err)
	}
}
