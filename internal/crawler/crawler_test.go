package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestCrawl_SameOrigin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body>
				<a href="/page1">Page 1</a>
				<a href="http://otherdomain.example/external">External</a>
				<a href="/page2">Page 2</a>
			</body></html>`)
		case "/page1":
			fmt.Fprint(w, `<html><body><a href="/page1/sub">Subpage</a></body></html>`)
		case "/page2":
			fmt.Fprint(w, `<html><body>Page 2 content</body></html>`)
		case "/page1/sub":
			fmt.Fprint(w, `<html><body>Subpage content</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	target := model.Target{Onion: ts.Listener.Addr().String()}
	limits := Limits{
		MaxPages:    10,
		MaxBodyByte: 1024 * 1024,
		PageTimeout: 5 * time.Second,
		TotalBudget: 10 * time.Second,
	}

	pages, err := Crawl(context.Background(), ts.Client(), target, limits)
	if err != nil {
		t.Fatalf("unexpected crawl error: %v", err)
	}

	expectedURLs := map[string]bool{
		"http://" + target.Onion + "/":          true,
		"http://" + target.Onion + "/page1":     true,
		"http://" + target.Onion + "/page2":     true,
		"http://" + target.Onion + "/page1/sub": true,
	}

	if len(pages) != len(expectedURLs) {
		t.Errorf("expected %d pages, got %d", len(expectedURLs), len(pages))
	}

	for _, p := range pages {
		if !expectedURLs[p.URL] {
			t.Errorf("unexpected URL fetched: %s", p.URL)
		}
		if strings.Contains(p.URL, "otherdomain.example") {
			t.Errorf("cross-origin URL should not have been fetched: %s", p.URL)
		}
	}
}

func TestCrawl_RespectsMaxPages(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Infinite chain: each page links to the next number
		var next int
		_, _ = fmt.Sscanf(r.URL.Path, "/page%d", &next)
		fmt.Fprintf(w, `<html><body><a href="/page%d">Next</a></body></html>`, next+1)
	}))
	defer ts.Close()

	target := model.Target{Onion: ts.Listener.Addr().String()}
	limits := Limits{
		MaxPages:    3,
		MaxBodyByte: 1024 * 1024,
		PageTimeout: 5 * time.Second,
		TotalBudget: 10 * time.Second,
	}

	pages, err := Crawl(context.Background(), ts.Client(), target, limits)
	if err != nil {
		t.Fatalf("unexpected crawl error: %v", err)
	}

	if len(pages) != 3 {
		t.Errorf("expected exactly 3 pages, got %d", len(pages))
	}
}

func TestCrawl_RespectsMaxBodyByte(t *testing.T) {
	largeBody := strings.Repeat("A", 10000)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, largeBody)
	}))
	defer ts.Close()

	target := model.Target{Onion: ts.Listener.Addr().String()}
	limits := Limits{
		MaxPages:    1,
		MaxBodyByte: 256,
		PageTimeout: 5 * time.Second,
		TotalBudget: 10 * time.Second,
	}

	pages, err := Crawl(context.Background(), ts.Client(), target, limits)
	if err != nil {
		t.Fatalf("unexpected crawl error: %v", err)
	}

	if len(pages) != 1 {
		t.Fatalf("expected 1 page, got %d", len(pages))
	}

	if len(pages[0].Body) != 256 {
		t.Errorf("expected body length capped at 256 bytes, got %d bytes", len(pages[0].Body))
	}
}

func TestCrawl_CrossOriginRedirectBlocked(t *testing.T) {
	var externalContacted bool
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalContacted = true
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("FOREIGN CONTENT - MUST NOT BE FETCHED"))
	}))
	defer externalServer.Close()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><a href="/escape">Escape</a></body></html>`))
		case "/escape":
			w.Header().Set("Location", externalServer.URL+"/forbidden")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("Redirecting to external site"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer targetServer.Close()

	target := model.Target{Onion: targetServer.Listener.Addr().String()}
	limits := Limits{
		MaxPages:    5,
		MaxBodyByte: 1024 * 1024,
		PageTimeout: 5 * time.Second,
		TotalBudget: 10 * time.Second,
	}

	pages, err := Crawl(context.Background(), targetServer.Client(), target, limits)
	if err != nil {
		t.Fatalf("unexpected crawl error: %v", err)
	}

	if externalContacted {
		t.Fatalf("security violation: crawler followed cross-origin redirect to external server %s", externalServer.URL)
	}

	// Should have fetched root / and /escape (which stopped at 302)
	var escapePage *model.Page
	for i := range pages {
		if strings.HasSuffix(pages[i].URL, "/escape") {
			escapePage = &pages[i]
			break
		}
	}

	if escapePage == nil {
		t.Fatalf("expected /escape page to be recorded, got pages: %+v", pages)
	}

	if escapePage.StatusCode != http.StatusFound {
		t.Errorf("expected status code 302, got %d", escapePage.StatusCode)
	}

	if strings.Contains(string(escapePage.Body), "FOREIGN CONTENT") {
		t.Errorf("crawler should not have fetched body of foreign redirect target")
	}

	if loc := escapePage.Headers["Location"]; loc != externalServer.URL+"/forbidden" {
		t.Errorf("expected Location header %s, got %s", externalServer.URL+"/forbidden", loc)
	}
}

func TestCrawl_CrossOriginRedirectToClearnetBlocked(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://clearnet.example.com/phish")
		w.WriteHeader(http.StatusMovedPermanently)
		_, _ = w.Write([]byte("Redirecting to clearnet"))
	}))
	defer targetServer.Close()

	target := model.Target{Onion: targetServer.Listener.Addr().String()}
	limits := Limits{
		MaxPages:    5,
		MaxBodyByte: 1024 * 1024,
		PageTimeout: 5 * time.Second,
		TotalBudget: 10 * time.Second,
	}

	pages, err := Crawl(context.Background(), targetServer.Client(), target, limits)
	if err != nil {
		t.Fatalf("unexpected crawl error: %v", err)
	}

	if len(pages) != 1 {
		t.Fatalf("expected 1 page recorded, got %d", len(pages))
	}

	if pages[0].StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected status 301, got %d", pages[0].StatusCode)
	}

	if pages[0].Headers["Location"] != "https://clearnet.example.com/phish" {
		t.Errorf("expected Location header to be preserved, got %s", pages[0].Headers["Location"])
	}

	// URL should remain the target URL, not clearnet
	expectedRoot := "http://" + target.Onion + "/"
	if pages[0].URL != expectedRoot {
		t.Errorf("expected page URL %s, got %s", expectedRoot, pages[0].URL)
	}
}

func TestCrawl_SameOriginRedirectFollowed(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><a href="/old-path">Old Path</a></body></html>`))
		case "/old-path":
			w.Header().Set("Location", "/new-path")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/new-path":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>New Path Content</h1><a href="/subpage">Sub</a></body></html>`))
		case "/subpage":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>Subpage Content</body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer targetServer.Close()

	target := model.Target{Onion: targetServer.Listener.Addr().String()}
	limits := Limits{
		MaxPages:    5,
		MaxBodyByte: 1024 * 1024,
		PageTimeout: 5 * time.Second,
		TotalBudget: 10 * time.Second,
	}

	pages, err := Crawl(context.Background(), targetServer.Client(), target, limits)
	if err != nil {
		t.Fatalf("unexpected crawl error: %v", err)
	}

	var foundNewPath, foundSubpage bool
	for _, p := range pages {
		if strings.HasSuffix(p.URL, "/new-path") {
			foundNewPath = true
			if p.StatusCode != http.StatusOK {
				t.Errorf("expected status 200 for redirected new-path, got %d", p.StatusCode)
			}
			if !strings.Contains(string(p.Body), "New Path Content") {
				t.Errorf("expected body to contain 'New Path Content'")
			}
		}
		if strings.HasSuffix(p.URL, "/subpage") {
			foundSubpage = true
		}
	}

	if !foundNewPath {
		t.Errorf("expected /new-path to be fetched following redirect")
	}
	if !foundSubpage {
		t.Errorf("expected /subpage discovered from redirected page to be fetched")
	}
}

func TestCrawl_SameOriginRedirectChainLimit(t *testing.T) {
	// Chain of redirects: /r1 -> /r2 -> ... -> /r10
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var step int
		if _, err := fmt.Sscanf(r.URL.Path, "/r%d", &step); err == nil {
			next := fmt.Sprintf("/r%d", step+1)
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer targetServer.Close()

	target := model.Target{Onion: targetServer.Listener.Addr().String()}
	limits := Limits{
		MaxPages:    5,
		MaxBodyByte: 1024 * 1024,
		PageTimeout: 2 * time.Second,
		TotalBudget: 5 * time.Second,
	}

	// Starting crawl directly on redirect loop
	_, links, err := fetchOne(context.Background(), targetServer.Client(), "http://"+target.Onion+"/r1", limits)
	// fetchOne should return an error when exceeding redirect limit
	if err == nil {
		t.Fatalf("expected error exceeding redirect limit, got links=%v", links)
	}
	if !strings.Contains(err.Error(), "stopped after 5 redirects") {
		t.Errorf("expected 'stopped after 5 redirects' error, got: %v", err)
	}
}
