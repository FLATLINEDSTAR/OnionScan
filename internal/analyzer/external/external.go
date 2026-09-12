// Package external parses <script src>, <img src>, and <link href> tags
// to identify external cross-origin resources (INFRA-003) and external tracking/analytics
// scripts (OPSEC-001).
package external

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script\b[^>]*?\bsrc=["']([^"']+)["']`)
	imgSrcRe    = regexp.MustCompile(`(?i)<img\b[^>]*?\bsrc=["']([^"']+)["']`)
	linkHrefRe  = regexp.MustCompile(`(?i)<link\b[^>]*?\bhref=["']([^"']+)["']`)

	trackingKeywords = []string{
		"google-analytics", "googletagmanager", "analytics", "tracking",
		"matomo", "plausible", "mixpanel", "hotjar", "connect.facebook.net",
		"mc.yandex.ru", "statcounter", "beacon",
	}
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "external" }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	body := string(page.Body)
	targetHost := normalizeHost(target.Onion)

	var externalResources []string
	var trackingScripts []string

	checkURL := func(raw string, isScript bool) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") {
			return
		}

		u, err := url.Parse(raw)
		if err != nil {
			return
		}

		// Handle protocol-relative URLs (//example.com/asset.js)
		if strings.HasPrefix(raw, "//") && u.Host == "" {
			parts := strings.SplitN(raw[2:], "/", 2)
			u.Host = parts[0]
		}

		if u.Host != "" && normalizeHost(u.Host) != targetHost {
			externalResources = append(externalResources, raw)
			if isScript && isTrackingScript(raw) {
				trackingScripts = append(trackingScripts, raw)
			}
		}
	}

	// Extract scripts
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			checkURL(m[1], true)
		}
	}

	// Extract images
	for _, m := range imgSrcRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			checkURL(m[1], false)
		}
	}

	// Extract links (stylesheets, icons, prefetch)
	for _, m := range linkHrefRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			checkURL(m[1], false)
		}
	}

	// Check Location header for cross-origin redirects
	for k, v := range page.Headers {
		if strings.EqualFold(k, "Location") && strings.TrimSpace(v) != "" {
			checkURL(v, false)
		}
	}

	externalResources = dedupe(externalResources)
	trackingScripts = dedupe(trackingScripts)

	var findings []model.Finding
	now := time.Now()

	// 1. External analytics/tracking scripts (OPSEC-001)
	if len(trackingScripts) > 0 {
		var ev []model.Evidence
		for _, s := range trackingScripts {
			ev = append(ev, model.Evidence{
				Type:        model.EvidenceExternalRes,
				Description: fmt.Sprintf("tracking script: %s", s),
				Source:      page.URL,
			})
		}

		findings = append(findings, model.Finding{
			ID:             "OPSEC-001",
			Title:          "External analytics/tracking script detected",
			Severity:       model.SeverityMedium,
			Confidence:     0.9,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       ev,
			Explanation:    "Third-party tracking or analytics scripts were loaded. These services may log visitor IPs, correlate onion service usage with clearnet identities, or deanonymize operators.",
			Recommendation: "Remove external tracking and analytics scripts from onion services.",
			CreatedAt:      now,
		})
	}

	// 2. External resources in general (INFRA-003)
	if len(externalResources) > 0 {
		var ev []model.Evidence
		for _, r := range externalResources {
			ev = append(ev, model.Evidence{
				Type:        model.EvidenceExternalRes,
				Description: r,
				Source:      page.URL,
			})
		}

		findings = append(findings, model.Finding{
			ID:             "INFRA-003",
			Title:          "External resources referenced in page content",
			Severity:       model.SeverityInfo,
			Confidence:     1.0,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       ev,
			Explanation:    "The page loads resources (scripts, images, stylesheets) from external domains outside the onion service. Loading external assets can cause clearnet leaks for visitors or expose infrastructure relationships.",
			Recommendation: "Host all assets locally on the onion service to prevent third-party network requests.",
			CreatedAt:      now,
		})
	}

	return findings, nil
}

func isTrackingScript(u string) bool {
	lower := strings.ToLower(u)
	for _, kw := range trackingKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	return h
}

func dedupe(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, it := range items {
		if it != "" && !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return out
}
