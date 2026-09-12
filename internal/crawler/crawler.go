// Package crawler fetches pages from a single onion Target over a provided
// *http.Client (normally Tor-routed, see internal/tor). It is deliberately
// conservative: same-origin only, hard caps on pages/body size/wall time.
// It never executes JavaScript found on the target -- see
// docs/ARCHITECTURE.md "Safety" section for why that's a hard rule.
package crawler

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// Limits bounds a single crawl so a hostile or misbehaving target can't
// exhaust scanner resources.
type Limits struct {
	MaxPages    int
	MaxBodyByte int64
	PageTimeout time.Duration
	TotalBudget time.Duration
}

// DefaultLimits is a conservative starting point; tune via config.
var DefaultLimits = Limits{
	MaxPages:    50,
	MaxBodyByte: 5 * 1024 * 1024, // 5MB per page
	PageTimeout: 20 * time.Second,
	TotalBudget: 5 * time.Minute,
}

const maxRedirects = 5

var hrefRe = regexp.MustCompile(`href=["']([^"'#]+)["']`)

// Crawl performs a breadth-first same-origin crawl starting at the target's
// root and returns every page fetched (bounded by limits).
func Crawl(ctx context.Context, client *http.Client, target model.Target, limits Limits) ([]model.Page, error) {
	root := "http://" + target.Onion + "/"
	rootURL, err := url.Parse(root)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target.Onion, err)
	}

	ctx, cancel := context.WithTimeout(ctx, limits.TotalBudget)
	defer cancel()

	if client == nil {
		client = http.DefaultClient
	}

	crawlClient := *client
	crawlClient.CheckRedirect = sameOriginRedirectPolicy(rootURL)

	seen := map[string]bool{}
	queue := []string{rootURL.String()}
	var pages []model.Page

	for len(queue) > 0 && len(pages) < limits.MaxPages {
		select {
		case <-ctx.Done():
			return pages, nil // budget exhausted; return what we have
		default:
		}

		next := queue[0]
		queue = queue[1:]
		if seen[next] {
			continue
		}
		seen[next] = true

		page, links, err := fetchOne(ctx, &crawlClient, next, limits)
		if err != nil {
			continue // one dead link shouldn't abort the whole crawl
		}

		if next != page.URL && seen[page.URL] {
			continue
		}
		seen[page.URL] = true
		pages = append(pages, page)

		for _, l := range links {
			abs, ok := resolveSameOrigin(rootURL, page.URL, l)
			if ok && !seen[abs] {
				queue = append(queue, abs)
			}
		}
	}

	return pages, nil
}

func sameOriginRedirectPolicy(rootURL *url.URL) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if !sameOrigin(rootURL, req.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func fetchOne(ctx context.Context, client *http.Client, target string, limits Limits) (model.Page, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, limits.PageTimeout)
	defer cancel()

	fetchClient := client
	if fetchClient == nil {
		fetchClient = http.DefaultClient
	}
	if fetchClient.CheckRedirect == nil {
		targetURL, err := url.Parse(target)
		if err != nil {
			return model.Page{}, nil, err
		}
		cloned := *fetchClient
		cloned.CheckRedirect = sameOriginRedirectPolicy(targetURL)
		fetchClient = &cloned
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return model.Page{}, nil, err
	}
	req.Header.Set("User-Agent", "OnionSec/0.1 (+authorized-scan)")

	resp, err := fetchClient.Do(req)
	if err != nil {
		return model.Page{}, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, limits.MaxBodyByte))
	if err != nil {
		return model.Page{}, nil, err
	}

	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	pageURL := target
	if resp.Request != nil && resp.Request.URL != nil {
		pageURL = resp.Request.URL.String()
	}

	page := model.Page{
		URL:        pageURL,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
		FetchedAt:  time.Now(),
	}

	var links []string
	if isHTML(headers) {
		for _, m := range hrefRe.FindAllStringSubmatch(string(body), -1) {
			links = append(links, m[1])
		}
	}

	return page, links, nil
}

func isHTML(headers map[string]string) bool {
	ct := headers["Content-Type"]
	return ct == "" || regexp.MustCompile(`(?i)text/html`).MatchString(ct)
}

func normalizeURLHost(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Host))
	h, p, err := net.SplitHostPort(host)
	if err == nil {
		if (u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443") {
			return h
		}
		return net.JoinHostPort(h, p)
	}
	return host
}

func sameOrigin(u1, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	h1 := normalizeURLHost(u1)
	h2 := normalizeURLHost(u2)
	return h1 != "" && h1 == h2
}

func resolveSameOrigin(root *url.URL, base, ref string) (string, bool) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	abs, err := baseURL.Parse(ref)
	if err != nil {
		return "", false
	}
	if !sameOrigin(root, abs) {
		return "", false // cross-origin links are noted as external resources elsewhere, not crawled
	}
	abs.Fragment = ""
	return abs.String(), true
}
