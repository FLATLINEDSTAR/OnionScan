package apidetect

import (
	"context"
	"strings"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_APIEndpointsInBody(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	html := `<!DOCTYPE html>
<html>
<body>
	<script>
		fetch('/api/v1/auth/login', {method: 'POST'});
		const gqlEndpoint = "/graphql";
	</script>
	<link rel="https://api.w.org/" href="http://test.onion/wp-json/">
</body>
</html>`

	page := model.Page{
		URL:  "http://test.onion/",
		Body: []byte(html),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FP-002" {
		t.Errorf("expected finding ID FP-002, got %s", f.ID)
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", f.Severity)
	}

	var foundAPI, foundGraphQL, foundWPJSON bool
	for _, e := range f.Evidence {
		if strings.Contains(e.Description, "/api/v1/auth/login") {
			foundAPI = true
		}
		if strings.Contains(e.Description, "/graphql") {
			foundGraphQL = true
		}
		if strings.Contains(e.Description, "/wp-json") {
			foundWPJSON = true
		}
	}

	if !foundAPI || !foundGraphQL || !foundWPJSON {
		t.Errorf("expected API, GraphQL, and wp-json evidence, got %+v", f.Evidence)
	}
}

func TestAnalyze_APIEndpointInPageURL(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/api/v2/products",
		Body: []byte(`{"status":"ok"}`),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FP-002" {
		t.Errorf("expected FP-002, got %s", f.ID)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Description != "/api/v2/products" {
		t.Errorf("expected /api/v2/products evidence, got %+v", f.Evidence)
	}
}

func TestAnalyze_CleanPage_NoFindings(t *testing.T) {
	a := New()
	target := model.Target{Onion: "clean.onion"}
	page := model.Page{
		URL:  "http://clean.onion/about",
		Body: []byte("<html><body><h1>About Us</h1><p>Welcome to our site!</p></body></html>"),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings on clean page, got %+v", findings)
	}
}
