// Package scan orchestrates a single end-to-end run: crawl -> analyze ->
// correlate -> score -> persist. This is the thing internal/analyzer's doc
// comment refers to as "the scan run" -- keep this file thin; real logic
// belongs in the packages it calls.
package scan

import (
	"context"
	"net/http"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/analyzer"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/apidetect"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/credentials"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/external"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/fingerprint"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/headers"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/jsanalysis"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/metadata"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/opsec"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/robots"
	"github.com/AryanXCode646/OnionScan/internal/analyzer/tls"
	"github.com/AryanXCode646/OnionScan/internal/correlation"
	"github.com/AryanXCode646/OnionScan/internal/crawler"
	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/risk"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

// DefaultRegistry returns the analyzer set every `onionsec scan` run uses.
// Community-contributed analyzers register here -- see CONTRIBUTING.md.
func DefaultRegistry() *analyzer.Registry {
	r := analyzer.NewRegistry()
	r.Register(headers.New())
	r.Register(opsec.New())
	r.Register(fingerprint.New())
	r.Register(tls.New())
	r.Register(robots.New())
	r.Register(jsanalysis.New())
	r.Register(external.New())
	r.Register(apidetect.New())
	r.Register(credentials.New())
	r.Register(metadata.New())
	return r
}

// Run performs a full scan of target using client for HTTP fetches
// (normally Tor-routed) and persists the result via store.
func Run(ctx context.Context, client *http.Client, store *storage.Store, target model.Target, limits crawler.Limits) (model.ScanResult, error) {
	started := time.Now()

	pages, err := crawler.Crawl(ctx, client, target, limits)
	if err != nil {
		return model.ScanResult{}, err
	}

	reg := DefaultRegistry()
	var findings []model.Finding
	for _, page := range pages {
		for _, a := range reg.All() {
			fs, err := a.Analyze(ctx, target, page)
			if err != nil {
				continue // one analyzer failing shouldn't sink the scan
			}
			findings = append(findings, fs...)
		}
	}

	findings = correlation.Correlate(target, findings)

	result := model.ScanResult{
		Target:    target,
		StartedAt: started,
		EndedAt:   time.Now(),
		PagesSeen: len(pages),
		Findings:  findings,
		RiskScore: risk.Score(findings),
	}

	if store != nil {
		if _, err := store.Save(result); err != nil {
			return result, err
		}
	}

	return result, nil
}
