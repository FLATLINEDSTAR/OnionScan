package jsanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_SourceMap_SEC003(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/assets/main.js",
		Body: []byte("function hello(){console.log('hi');}\n//# sourceMappingURL=main.js.map"),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundSEC003 bool
	for _, f := range findings {
		if f.ID == "SEC-003" {
			foundSEC003 = true
			if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0].Description, "main.js.map") {
				t.Errorf("unexpected evidence: %+v", f.Evidence)
			}
		}
	}

	if !foundSEC003 {
		t.Errorf("expected SEC-003 finding for source map reference, got %+v", findings)
	}
}

func TestAnalyze_BuildPaths_OPSEC009(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	jsContent := `
var mod = webpack:///./src/components/Header.tsx;
var path = "/home/alice/projects/onion-site/node_modules/lodash/lodash.js";
import(/* webpackChunkName: "dashboard-view" */ './Dashboard');
`
	page := model.Page{
		URL:  "http://test.onion/bundle.js",
		Body: []byte(jsContent),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundOPSEC009 bool
	for _, f := range findings {
		if f.ID == "OPSEC-009" {
			foundOPSEC009 = true
			if len(f.Evidence) < 2 {
				t.Errorf("expected multiple evidence items for build disclosures, got %+v", f.Evidence)
			}
		}
	}

	if !foundOPSEC009 {
		t.Errorf("expected OPSEC-009 finding for build paths, got %+v", findings)
	}
}

func TestAnalyze_CleanJS_NoFindings(t *testing.T) {
	a := New()
	target := model.Target{Onion: "clean.onion"}
	page := model.Page{
		URL:  "http://clean.onion/clean.js",
		Body: []byte("!function(e){var t={};function n(r){return t[r]||(t[r]={exports:{}})}n(0)}([function(e,t){}]);"),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean JS, got %+v", findings)
	}
}
