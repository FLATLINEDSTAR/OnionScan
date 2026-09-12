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
		fmt.Sscanf(r.URL.Path, "/page%d", &next)
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
