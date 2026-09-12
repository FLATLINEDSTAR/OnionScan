// Package apidetect identifies common REST and GraphQL API endpoint patterns
// referenced in page content or discovered during a crawl (FP-002).
// These informational findings feed the correlation engine for service stack mapping.
package apidetect

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

var (
	// Matches common API endpoint paths in content and URLs
	apiPatternRe = regexp.MustCompile(`(?i)(?:["']|href=|src=)?((?:https?://[^/\s"'>]+)?/(?:api(?:/[a-zA-Z0-9_\-]+)*|graphql|v[1-9]\d*(?:/[a-zA-Z0-9_\-]+)*|wp-json(?:/[a-zA-Z0-9_\-]+)*|swagger(?:/[a-zA-Z0-9_\-]+)*|openapi\.json|swagger\.json|rpc|jsonrpc))\b`)
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "apidetect" }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	var endpoints []string

	// Check page URL itself
	if u, err := url.Parse(page.URL); err == nil {
		if isAPIPath(u.Path) {
			endpoints = append(endpoints, u.Path)
		}
	}

	// Check page body content
	body := string(page.Body)
	matches := apiPatternRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			raw := strings.Trim(m[1], `"'=`)
			if u, err := url.Parse(raw); err == nil && u.Path != "" {
				if isAPIPath(u.Path) {
					endpoints = append(endpoints, u.Path)
				}
			} else if isAPIPath(raw) {
				endpoints = append(endpoints, raw)
			}
		}
	}

	endpoints = dedupe(endpoints)
	if len(endpoints) == 0 {
		return nil, nil
	}

	var ev []model.Evidence
	for _, ep := range endpoints {
		ev = append(ev, model.Evidence{
			Type:        model.EvidenceMetadata,
			Description: ep,
			Source:      page.URL,
		})
		if len(ev) >= 15 {
			break
		}
	}

	return []model.Finding{
		{
			ID:             "FP-002",
			Title:          "API endpoint pattern detected",
			Severity:       model.SeverityInfo,
			Confidence:     0.95,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       ev,
			Explanation:    "Common REST, GraphQL, or RPC API endpoints were detected in page content or URLs. This records the service's API interface for stack identification and correlation.",
			Recommendation: "Informational; verify that sensitive administrative API endpoints require strong authentication and are not exposed unintentionally.",
			CreatedAt:      time.Now(),
		},
	}, nil
}

func isAPIPath(p string) bool {
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, "/api"),
		strings.HasPrefix(lower, "/graphql"),
		strings.HasPrefix(lower, "/v1/"),
		strings.HasPrefix(lower, "/v2/"),
		strings.HasPrefix(lower, "/wp-json"),
		strings.HasPrefix(lower, "/swagger"),
		strings.HasPrefix(lower, "/rpc"),
		strings.HasPrefix(lower, "/jsonrpc"),
		strings.Contains(lower, "openapi.json"),
		strings.Contains(lower, "swagger.json"):
		return true
	default:
		return false
	}
}

func dedupe(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" && !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return out
}
