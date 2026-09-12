package external

import (
	"context"
	"strings"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_ExternalTrackingScript(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	html := `<!DOCTYPE html>
<html>
<head>
	<script src="https://www.google-analytics.com/analytics.js"></script>
	<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">
</head>
<body>
	<img src="https://cdn.example.org/banner.jpg">
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

	var foundOPSEC001, foundINFRA003 bool
	for _, f := range findings {
		if f.ID == "OPSEC-001" {
			foundOPSEC001 = true
			if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0].Description, "google-analytics") {
				t.Errorf("expected analytics script in OPSEC-001 evidence, got %+v", f.Evidence)
			}
		}
		if f.ID == "INFRA-003" {
			foundINFRA003 = true
			if len(f.Evidence) != 3 {
				t.Errorf("expected 3 external resources in INFRA-003, got %d", len(f.Evidence))
			}
		}
	}

	if !foundOPSEC001 {
		t.Errorf("expected OPSEC-001 finding for google-analytics")
	}
	if !foundINFRA003 {
		t.Errorf("expected INFRA-003 finding for external resources")
	}
}

func TestAnalyze_ExternalAssetsWithoutTracking(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	html := `<html><body>
		<img src="https://images.example.com/photo.png">
		<link rel="stylesheet" href="//cdn.style.net/app.css">
	</body></html>`

	page := model.Page{
		URL:  "http://test.onion/",
		Body: []byte(html),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundINFRA003 := false
	for _, f := range findings {
		if f.ID == "OPSEC-001" {
			t.Errorf("did not expect OPSEC-001 for non-tracking assets, got %+v", f)
		}
		if f.ID == "INFRA-003" {
			foundINFRA003 = true
		}
	}

	if !foundINFRA003 {
		t.Errorf("expected INFRA-003 for external assets")
	}
}

func TestAnalyze_InternalAssetsOnly_NoFindings(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	html := `<html>
	<head>
		<script src="/static/js/main.js"></script>
		<link rel="stylesheet" href="/static/css/style.css">
		<script src="http://test.onion/app.js"></script>
	</head>
	<body>
		<img src="/static/img/logo.png">
		<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==">
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

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for local-only resources, got %+v", findings)
	}
}

func TestAnalyze_CrossOriginRedirect_LocationHeader(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:        "http://test.onion/login",
		StatusCode: 302,
		Headers: map[string]string{
			"Location": "https://external.example.com/oauth/callback",
		},
		Body: []byte("Redirecting..."),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundINFRA003 bool
	for _, f := range findings {
		if f.ID == "INFRA-003" {
			foundINFRA003 = true
			if len(f.Evidence) != 1 || f.Evidence[0].Description != "https://external.example.com/oauth/callback" {
				t.Errorf("expected Location URL in evidence, got: %+v", f.Evidence)
			}
		}
	}

	if !foundINFRA003 {
		t.Errorf("expected INFRA-003 finding for cross-origin Location redirect")
	}
}
