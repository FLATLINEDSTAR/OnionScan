package opsec

import (
	"context"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_EmailDisclosure(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/contact",
		Body: []byte("Contact support at admin@example.com for assistance."),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.ID == "OPSEC-002" {
			found = true
			if len(f.Evidence) != 1 || f.Evidence[0].Description != "admin@example.com" {
				t.Errorf("unexpected evidence for OPSEC-002: %+v", f.Evidence)
			}
		}
	}
	if !found {
		t.Errorf("expected OPSEC-002 finding for email disclosure, got %+v", findings)
	}
}

func TestAnalyze_PublicIPDisclosure(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/status",
		Body: []byte("Server located at 93.184.216.34 (US datacenter)."),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.ID == "INFRA-001" {
			found = true
			if len(f.Evidence) != 1 || f.Evidence[0].Description != "93.184.216.34" {
				t.Errorf("unexpected evidence for INFRA-001: %+v", f.Evidence)
			}
		}
	}
	if !found {
		t.Errorf("expected INFRA-001 finding for public IP disclosure, got %+v", findings)
	}
}

func TestAnalyze_PrivateIPDisclosure(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/error",
		Body: []byte("Upstream backend 10.0.1.5:8080 timed out."),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.ID == "OPSEC-007" {
			found = true
			if len(f.Evidence) != 1 || f.Evidence[0].Description != "10.0.1.5" {
				t.Errorf("unexpected evidence for OPSEC-007: %+v", f.Evidence)
			}
		}
	}
	if !found {
		t.Errorf("expected OPSEC-007 finding for private IP disclosure, got %+v", findings)
	}
}

func TestAnalyze_NoDisclosure(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/about",
		Body: []byte("Welcome to our secure onion service. No identifiers here!"),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings on clean page, got %+v", findings)
	}
}
