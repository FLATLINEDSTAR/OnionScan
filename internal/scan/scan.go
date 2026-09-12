// Package scan orchestrates a single end-to-end run: crawl -> analyze ->
// correlate -> score -> persist. This is the thing internal/analyzer's doc
// comment refers to as "the scan run" -- keep this file thin; real logic
// belongs in the packages it calls.
package scan

import (
	"context"
	"net"
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

// DefaultRegistry returns the default analyzer set.
func DefaultRegistry() *analyzer.Registry {
	return NewRegistryWithClient(nil)
}

// NewRegistryWithClient returns an analyzer registry with network-fetching
// analyzers (tls, robots, metadata) configured to route traffic through the
// provided HTTP client and its underlying dialer.
func NewRegistryWithClient(client *http.Client) *analyzer.Registry {
	r := analyzer.NewRegistry()
	r.Register(headers.New())
	r.Register(opsec.New())
	r.Register(fingerprint.New())

	var dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if client != nil {
		if tr, ok := client.Transport.(*http.Transport); ok && tr.DialContext != nil {
			dialContext = tr.DialContext
		}
	}

	if dialContext != nil {
		r.Register(tls.NewWithDialContext(dialContext))
	} else {
		r.Register(tls.New())
	}

	if client != nil {
		r.Register(robots.NewWithClient(client))
		r.Register(metadata.NewWithClient(client))
	} else {
		r.Register(robots.New())
		r.Register(metadata.New())
	}

	r.Register(jsanalysis.New())
	r.Register(external.New())
	r.Register(apidetect.New())
	r.Register(credentials.New())
	return r
}

// Run performs a full scan of target using client for HTTP fetches
// (normally Tor-routed) and persists the result via store.
func Run(ctx context.Context, client *http.Client, store storage.Store, target model.Target, limits crawler.Limits) (model.ScanResult, error) {
	started := time.Now()

	pages, err := crawler.Crawl(ctx, client, target, limits)
	if err != nil {
		return model.ScanResult{}, err
	}

	reg := NewRegistryWithClient(client)
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

	findings = correlation.CorrelateWithStore(target, findings, store)

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
