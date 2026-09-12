package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/crawler"
	"github.com/AryanXCode646/OnionScan/internal/tor"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SOCKSAddr != tor.DefaultSOCKSAddr {
		t.Errorf("expected default SOCKS addr %s, got %s", tor.DefaultSOCKSAddr, cfg.SOCKSAddr)
	}
	if cfg.Limits.MaxPages != crawler.DefaultLimits.MaxPages {
		t.Errorf("expected default max pages %d, got %d", crawler.DefaultLimits.MaxPages, cfg.Limits.MaxPages)
	}
}

func TestParse_FullYAML(t *testing.T) {
	yamlInput := `
# OnionSec configuration
socks_addr: "127.0.0.1:9150"
max_pages: 100 # custom page limit
max_body_bytes: 10MB
page_timeout: 15s
total_budget: 3m
`
	base := DefaultConfig()
	cfg, err := Parse(strings.NewReader(yamlInput), base)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if cfg.SOCKSAddr != "127.0.0.1:9150" {
		t.Errorf("expected SOCKS addr 127.0.0.1:9150, got %s", cfg.SOCKSAddr)
	}
	if cfg.Limits.MaxPages != 100 {
		t.Errorf("expected max pages 100, got %d", cfg.Limits.MaxPages)
	}
	if cfg.Limits.MaxBodyByte != 10*1024*1024 {
		t.Errorf("expected max body 10485760, got %d", cfg.Limits.MaxBodyByte)
	}
	if cfg.Limits.PageTimeout != 15*time.Second {
		t.Errorf("expected page timeout 15s, got %v", cfg.Limits.PageTimeout)
	}
	if cfg.Limits.TotalBudget != 3*time.Minute {
		t.Errorf("expected total budget 3m, got %v", cfg.Limits.TotalBudget)
	}
}

func TestLoadFile(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "config.yaml")

	content := `
socks_addr: 10.0.0.1:9050
max_pages: 25
`
	if err := os.WriteFile(confPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := LoadFile(confPath, true)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if cfg.SOCKSAddr != "10.0.0.1:9050" {
		t.Errorf("expected SOCKS addr 10.0.0.1:9050, got %s", cfg.SOCKSAddr)
	}
	if cfg.Limits.MaxPages != 25 {
		t.Errorf("expected max pages 25, got %d", cfg.Limits.MaxPages)
	}
	// Other fields should retain defaults
	if cfg.Limits.TotalBudget != crawler.DefaultLimits.TotalBudget {
		t.Errorf("expected default total budget, got %v", cfg.Limits.TotalBudget)
	}

	// Missing explicit file should error
	_, err = LoadFile(filepath.Join(tempDir, "nonexistent.yaml"), true)
	if err == nil {
		t.Errorf("expected error for missing explicit file")
	}

	// Missing non-explicit file should return default config without error
	fallbackCfg, err := LoadFile(filepath.Join(tempDir, "nonexistent.yaml"), false)
	if err != nil {
		t.Errorf("expected no error for non-explicit fallback, got %v", err)
	}
	if fallbackCfg.SOCKSAddr != tor.DefaultSOCKSAddr {
		t.Errorf("expected default SOCKS addr, got %s", fallbackCfg.SOCKSAddr)
	}
}
