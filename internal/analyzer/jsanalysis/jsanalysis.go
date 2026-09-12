// Package jsanalysis performs static-only analysis of JavaScript bundles
// and inline scripts to detect source map references (SEC-003) and build/framework
// environment disclosures (OPSEC-009).
//
// Safety rule: this analyzer strictly performs static regex analysis and must
// never execute target-supplied JavaScript under any circumstance.
package jsanalysis

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

var (
	sourceMapRe    = regexp.MustCompile(`(?i)[#@]\s*sourceMappingURL\s*=\s*([^\s'"]+)`)
	mapExtensionRe = regexp.MustCompile(`(?i)\b([a-zA-Z0-9_\-\.\/]+\.js\.map)\b`)
	buildPathRe    = regexp.MustCompile(`\b(?:webpack:\/\/\S*|\/Users\/[a-zA-Z0-9_\.\-]+\/\S*|\/home\/[a-zA-Z0-9_\.\-]+\/\S*|node_modules\/[a-zA-Z0-9_\.\-]+\/\S*)\b`)
	chunkCommentRe = regexp.MustCompile(`\/\*\s*webpack(?:ChunkName|Mode|Prefetch|Preload):\s*["']?([^"'*]+)["']?\s*\*\/`)
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "jsanalysis" }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	var findings []model.Finding
	now := time.Now()
	content := string(page.Body)

	// 1. Detect Source Map references (SEC-003)
	var mapRefs []string
	for _, m := range sourceMapRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			mapRefs = append(mapRefs, m[1])
		}
	}
	for _, m := range mapExtensionRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			mapRefs = append(mapRefs, m[1])
		}
	}
	mapRefs = dedupe(mapRefs)

	if len(mapRefs) > 0 {
		var ev []model.Evidence
		for _, ref := range mapRefs {
			ev = append(ev, model.Evidence{
				Type:        model.EvidenceMetadata,
				Description: fmt.Sprintf("source map reference: %s", ref),
				Source:      page.URL,
			})
			if len(ev) >= 10 {
				break
			}
		}

		findings = append(findings, model.Finding{
			ID:             "SEC-003",
			Title:          "JavaScript source map reference disclosed",
			Severity:       model.SeverityLow,
			Confidence:     0.95,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       ev,
			Explanation:    "A JavaScript source map (.map) reference was discovered. If exposed, source maps reveal the original unminified application source code, file structures, and internal developer comments.",
			Recommendation: "Disable source map generation in production builds, or avoid publishing source map files and sourceMappingURL comments publicly.",
			CreatedAt:      now,
		})
	}

	// 2. Detect Build environment and developer paths (OPSEC-009)
	var buildPaths []string
	for _, m := range buildPathRe.FindAllString(content, -1) {
		// Clean up trailing punctuation
		p := strings.TrimRight(m, `"',;()`)
		buildPaths = append(buildPaths, p)
	}
	for _, m := range chunkCommentRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			buildPaths = append(buildPaths, fmt.Sprintf("webpackChunk: %s", strings.TrimSpace(m[1])))
		}
	}
	buildPaths = dedupe(buildPaths)

	if len(buildPaths) > 0 {
		var ev []model.Evidence
		for _, p := range buildPaths {
			ev = append(ev, model.Evidence{
				Type:        model.EvidenceMetadata,
				Description: p,
				Source:      page.URL,
			})
			if len(ev) >= 10 {
				break
			}
		}

		findings = append(findings, model.Finding{
			ID:             "OPSEC-009",
			Title:          "Build environment or local file paths disclosed in JavaScript",
			Severity:       model.SeverityLow,
			Confidence:     0.85,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       ev,
			Explanation:    "Local filesystem paths (e.g. /home/..., /Users/...), webpack:// prefixes, or development chunk comments were found in JavaScript. These disclose developer machine usernames and directory structure.",
			Recommendation: "Configure bundlers (such as Webpack, Vite, Rollup) to strip source comments and normalize module identifiers in production builds.",
			CreatedAt:      now,
		})
	}

	return findings, nil
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
