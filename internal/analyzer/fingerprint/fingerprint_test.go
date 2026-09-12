package fingerprint

import (
	"context"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_EmitsFingerprintFinding(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL: "http://test.onion/",
		Headers: map[string]string{
			"Server":       "nginx",
			"Content-Type": "text/html",
		},
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FP-001" {
		t.Errorf("expected finding ID FP-001, got %s", f.ID)
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", f.Severity)
	}
	if f.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", f.Confidence)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Type != model.EvidenceFingerprint {
		t.Errorf("expected 1 fingerprint evidence, got %+v", f.Evidence)
	}
	if f.Evidence[0].Description == "" {
		t.Errorf("expected non-empty fingerprint signature")
	}
}

func TestSignature_IdenticalHeadersProduceSameSignature(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}

	page1 := model.Page{
		URL: "http://test.onion/page1",
		Headers: map[string]string{
			"Server":       "Apache",
			"Content-Type": "text/html; charset=utf-8",
			"X-Powered-By": "PHP/8.1",
		},
	}

	page2 := model.Page{
		URL: "http://test.onion/page2",
		Headers: map[string]string{
			"X-Powered-By": "PHP/8.1",
			"Server":       "Apache",
			"Content-Type": "text/html; charset=utf-8",
		},
	}

	f1, err := a.Analyze(context.Background(), target, page1)
	if err != nil {
		t.Fatalf("unexpected error on page1: %v", err)
	}
	f2, err := a.Analyze(context.Background(), target, page2)
	if err != nil {
		t.Fatalf("unexpected error on page2: %v", err)
	}

	sig1 := f1[0].Evidence[0].Description
	sig2 := f2[0].Evidence[0].Description

	if sig1 != sig2 {
		t.Errorf("expected identical signatures for identical headers, got %q vs %q", sig1, sig2)
	}
}

func TestSignature_DifferentHeadersProduceDifferentSignatures(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}

	page1 := model.Page{
		URL: "http://test.onion/page1",
		Headers: map[string]string{
			"Server":       "Apache",
			"Content-Type": "text/html",
		},
	}

	page2 := model.Page{
		URL: "http://test.onion/page2",
		Headers: map[string]string{
			"Server":       "nginx",
			"Content-Type": "text/html",
		},
	}

	f1, err := a.Analyze(context.Background(), target, page1)
	if err != nil {
		t.Fatalf("unexpected error on page1: %v", err)
	}
	f2, err := a.Analyze(context.Background(), target, page2)
	if err != nil {
		t.Fatalf("unexpected error on page2: %v", err)
	}

	sig1 := f1[0].Evidence[0].Description
	sig2 := f2[0].Evidence[0].Description

	if sig1 == sig2 {
		t.Errorf("expected different signatures for different headers, got identical %q", sig1)
	}
}
