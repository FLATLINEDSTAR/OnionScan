package robots

import (
	"context"
	"strings"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_RobotsTxt_SensitivePaths(t *testing.T) {
	robotsContent := `
User-agent: *
Disallow: /admin/
Disallow: /debug/pprof
Disallow: /images/
Disallow: /static/
`
	a := New()
	a.Fetch = nil // test direct page parsing

	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/robots.txt",
		Body: []byte(robotsContent),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "OPSEC-004" {
		t.Errorf("expected finding ID OPSEC-004, got %s", f.ID)
	}
	if f.Severity != model.SeverityLow {
		t.Errorf("expected SeverityLow, got %v", f.Severity)
	}

	foundAdmin := false
	foundDebug := false
	for _, e := range f.Evidence {
		if strings.Contains(e.Description, "/admin/") {
			foundAdmin = true
		}
		if strings.Contains(e.Description, "/debug/pprof") {
			foundDebug = true
		}
		if strings.Contains(e.Description, "/static/") || strings.Contains(e.Description, "/images/") {
			t.Errorf("innocuous paths should not be flagged: %s", e.Description)
		}
	}

	if !foundAdmin || !foundDebug {
		t.Errorf("expected admin and debug paths in evidence, got %+v", f.Evidence)
	}
}

func TestAnalyze_SitemapXML_SensitivePaths(t *testing.T) {
	sitemapContent := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>http://test.onion/public/about</loc>
  </url>
  <url>
    <loc>http://test.onion/internal/dashboard</loc>
  </url>
</urlset>`

	a := New()
	a.Fetch = nil

	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL:  "http://test.onion/sitemap.xml",
		Body: []byte(sitemapContent),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "OPSEC-004" {
		t.Errorf("expected finding ID OPSEC-004, got %s", f.ID)
	}

	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0].Description, "/internal/dashboard") {
		t.Errorf("expected internal/dashboard evidence, got %+v", f.Evidence)
	}
}

func TestAnalyze_CleanRobots_NoFindings(t *testing.T) {
	cleanContent := `
User-agent: *
Disallow: /css/
Disallow: /assets/
`
	a := New()
	a.Fetch = nil

	target := model.Target{Onion: "clean.onion"}
	page := model.Page{
		URL:  "http://clean.onion/robots.txt",
		Body: []byte(cleanContent),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean robots.txt, got %+v", findings)
	}
}

func TestAnalyze_RootPage_FetchesRobotsAndSitemap(t *testing.T) {
	a := New()
	a.Fetch = func(ctx context.Context, url string) ([]byte, int, error) {
		if strings.HasSuffix(url, "/robots.txt") {
			return []byte("User-agent: *\nDisallow: /admin\n"), 200, nil
		}
		if strings.HasSuffix(url, "/sitemap.xml") {
			return []byte("<urlset><url><loc>http://test.onion/cpanel</loc></url></urlset>"), 200, nil
		}
		return nil, 404, nil
	}

	target := model.Target{Onion: "fetched.onion"}
	page := model.Page{
		URL:  "http://fetched.onion/",
		Body: []byte("<html><body>Welcome</body></html>"),
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "OPSEC-004" {
		t.Errorf("expected OPSEC-004 finding, got %s", f.ID)
	}

	if len(f.Evidence) != 2 {
		t.Errorf("expected 2 evidence items (from robots and sitemap), got %d", len(f.Evidence))
	}
}
