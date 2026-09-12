// Package robots inspects robots.txt and sitemap.xml for references to hidden
// administrative, debug, or internal endpoints (OPSEC-004).
//
// Safety rule: this analyzer strictly parses metadata and never automatically
// visits or crawls discovered disallowed/admin endpoints.
package robots

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

var (
	disallowRe        = regexp.MustCompile(`(?i)^\s*Disallow\s*:\s*(\S+)`)
	sitemapLocRe      = regexp.MustCompile(`(?i)<loc>\s*(https?://[^<\s]+)\s*</loc>`)
	sensitiveKeywords = []string{
		"admin", "administrator", "debug", "dashboard", "panel",
		"internal", "backup", "config", "phpmyadmin", "cpanel",
		"server-status", "metrics", "actuator", "staging", ".env",
	}
)

type Analyzer struct {
	// Fetch allows mocking HTTP requests in tests or using Tor client.
	Fetch func(ctx context.Context, url string) ([]byte, int, error)

	visitedMu sync.Mutex
	visited   map[string]bool
}

func New() *Analyzer {
	return &Analyzer{
		Fetch:   defaultFetch,
		visited: make(map[string]bool),
	}
}

func (a *Analyzer) Name() string { return "robots" }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	var suspiciousPaths []model.Evidence

	// If the current page itself is robots.txt or sitemap.xml, parse it directly
	if strings.HasSuffix(page.URL, "/robots.txt") {
		suspiciousPaths = append(suspiciousPaths, ParseRobotsTxt(page.Body, page.URL)...)
	} else if strings.HasSuffix(page.URL, "/sitemap.xml") {
		suspiciousPaths = append(suspiciousPaths, ParseSitemapXML(page.Body, page.URL)...)
	}

	// For the root page, fetch robots.txt and sitemap.xml once if configured
	a.visitedMu.Lock()
	if a.visited == nil {
		a.visited = make(map[string]bool)
	}
	alreadyChecked := a.visited[target.Onion]
	if !alreadyChecked {
		a.visited[target.Onion] = true
	}
	a.visitedMu.Unlock()

	if !alreadyChecked && a.Fetch != nil {
		robotsURL := "http://" + target.Onion + "/robots.txt"
		if body, code, err := a.Fetch(ctx, robotsURL); err == nil && code == 200 {
			suspiciousPaths = append(suspiciousPaths, ParseRobotsTxt(body, robotsURL)...)
		}

		sitemapURL := "http://" + target.Onion + "/sitemap.xml"
		if body, code, err := a.Fetch(ctx, sitemapURL); err == nil && code == 200 {
			suspiciousPaths = append(suspiciousPaths, ParseSitemapXML(body, sitemapURL)...)
		}
	}

	// Deduplicate evidence
	suspiciousPaths = dedupeEvidence(suspiciousPaths)

	if len(suspiciousPaths) == 0 {
		return nil, nil
	}

	return []model.Finding{
		{
			ID:             "OPSEC-004",
			Title:          "Debug/admin endpoint exposed",
			Severity:       model.SeverityLow,
			Confidence:     0.85,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       suspiciousPaths,
			Explanation:    "The robots.txt or sitemap.xml file references administrative, debug, or internal paths. Even though crawlers are requested not to index them, listing them publicly exposes their existence and location.",
			Recommendation: "Remove sensitive endpoint paths from public robots.txt and sitemap files, and rely on server-side authentication instead of obscurity.",
			CreatedAt:      time.Now(),
		},
	}, nil
}

// ParseRobotsTxt parses disallowed paths and identifies sensitive endpoints.
func ParseRobotsTxt(body []byte, sourceURL string) []model.Evidence {
	var ev []model.Evidence
	scanner := bufio.NewScanner(bytes.NewReader(body))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if m := disallowRe.FindStringSubmatch(line); len(m) > 1 {
			path := strings.TrimSpace(m[1])
			if path == "" || path == "/" {
				continue
			}
			if isSensitivePath(path) {
				ev = append(ev, model.Evidence{
					Type:        model.EvidenceMetadata,
					Description: fmt.Sprintf("disallowed path: %s", path),
					Source:      sourceURL,
				})
			}
		}
	}

	return ev
}

// ParseSitemapXML parses URL locations in sitemaps and identifies sensitive endpoints.
func ParseSitemapXML(body []byte, sourceURL string) []model.Evidence {
	var ev []model.Evidence
	matches := sitemapLocRe.FindAllSubmatch(body, -1)

	for _, m := range matches {
		if len(m) > 1 {
			loc := string(m[1])
			if isSensitivePath(loc) {
				ev = append(ev, model.Evidence{
					Type:        model.EvidenceMetadata,
					Description: fmt.Sprintf("sitemap URL: %s", loc),
					Source:      sourceURL,
				})
			}
		}
	}

	return ev
}

func isSensitivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func dedupeEvidence(ev []model.Evidence) []model.Evidence {
	seen := make(map[string]bool)
	var out []model.Evidence
	for _, e := range ev {
		key := fmt.Sprintf("%s:%s", e.Type, e.Description)
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}

func defaultFetch(ctx context.Context, urlStr string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "OnionSec/0.1 (+authorized-scan)")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	// Limit to 512KB for robots/sitemap
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
