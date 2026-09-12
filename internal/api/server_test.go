package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/crawler"
	"github.com/AryanXCode646/OnionScan/internal/diff"
	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

func setupTestServer(t *testing.T, authToken string) (*Server, storage.Store, string) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "onionsec.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed: %v", err)
	}

	limits := crawler.Limits{
		MaxPages:    5,
		MaxBodyByte: 1048576,
		PageTimeout: 2 * time.Second,
		TotalBudget: 10 * time.Second,
	}

	srv := NewServer(store, http.DefaultClient, limits, authToken)
	return srv, store, dbPath
}

func TestHealthz(t *testing.T) {
	srv, store, _ := setupTestServer(t, "test-secret")
	defer store.Close()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp["status"] != "healthy" {
		t.Errorf("expected status healthy, got %v", resp["status"])
	}
}

func TestAuthMiddleware(t *testing.T) {
	srv, store, _ := setupTestServer(t, "secret-token")
	defer store.Close()

	// 1. Missing auth header -> 401
	req1 := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	rec1 := httptest.NewRecorder()
	srv.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", rec1.Code)
	}

	// 2. Wrong Bearer token -> 401
	req2 := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	req2.Header.Set("Authorization", "Bearer wrong-token")
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", rec2.Code)
	}

	// 3. Correct Bearer token -> 200
	req3 := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	req3.Header.Set("Authorization", "Bearer secret-token")
	rec3 := httptest.NewRecorder()
	srv.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expected 200 with Bearer token, got %d", rec3.Code)
	}

	// 4. Correct X-API-Key -> 200
	req4 := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	req4.Header.Set("X-API-Key", "secret-token")
	rec4 := httptest.NewRecorder()
	srv.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Errorf("expected 200 with X-API-Key, got %d", rec4.Code)
	}
}

func TestCORSHeaders(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	defer store.Close()

	req := httptest.NewRequest(http.MethodOptions, "/v1/targets", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS preflight, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected CORS Allow-Origin *, got %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestEndpoints_ScansAndHistory(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	defer store.Close()

	// Mock target server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>contact: test@example.com</body></html>`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	targetHost := u.Host
	srv.TorClient = ts.Client()

	// 1. POST /v1/scans
	body, _ := json.Marshal(scanRequest{
		Target: targetHost,
		Async:  false,
	})
	reqPost := httptest.NewRequest(http.MethodPost, "/v1/scans", bytes.NewReader(body))
	reqPost.Header.Set("Content-Type", "application/json")
	recPost := httptest.NewRecorder()
	srv.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", recPost.Code, recPost.Body.String())
	}

	var scanResp scanCreatedResponse
	if err := json.Unmarshal(recPost.Body.Bytes(), &scanResp); err != nil {
		t.Fatalf("unmarshal scan response failed: %v", err)
	}
	if scanResp.Target != targetHost || scanResp.ID == "" {
		t.Fatalf("unexpected scan created response: %+v", scanResp)
	}

	// 2. GET /v1/targets
	reqTargets := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	recTargets := httptest.NewRecorder()
	srv.ServeHTTP(recTargets, reqTargets)
	if recTargets.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/targets, got %d", recTargets.Code)
	}
	var targetsMap map[string][]targetSummary
	_ = json.Unmarshal(recTargets.Body.Bytes(), &targetsMap)
	if len(targetsMap["targets"]) != 1 || targetsMap["targets"][0].Onion != targetHost {
		t.Fatalf("expected target in list, got %+v", targetsMap)
	}

	// 3. GET /v1/scans/{id}?target=...
	reqGetScan := httptest.NewRequest(http.MethodGet, "/v1/scans/"+scanResp.ID+"?target="+targetHost, nil)
	recGetScan := httptest.NewRecorder()
	srv.ServeHTTP(recGetScan, reqGetScan)
	if recGetScan.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/scans/{id}, got %d: %s", recGetScan.Code, recGetScan.Body.String())
	}

	// 4. GET /v1/history?target=...
	reqHist := httptest.NewRequest(http.MethodGet, "/v1/history?target="+targetHost, nil)
	recHist := httptest.NewRecorder()
	srv.ServeHTTP(recHist, reqHist)
	if recHist.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/history, got %d", recHist.Code)
	}
	var histMap map[string]interface{}
	_ = json.Unmarshal(recHist.Body.Bytes(), &histMap)
	if histMap["target"] != targetHost {
		t.Errorf("expected target in history response, got %+v", histMap)
	}

	// 5. GET /v1/findings?target=...
	reqFind := httptest.NewRequest(http.MethodGet, "/v1/findings?target="+targetHost, nil)
	recFind := httptest.NewRecorder()
	srv.ServeHTTP(recFind, reqFind)
	if recFind.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/findings, got %d", recFind.Code)
	}
	var findMap map[string]interface{}
	_ = json.Unmarshal(recFind.Body.Bytes(), &findMap)
	if findMap["total"].(float64) < 1 {
		t.Errorf("expected at least 1 finding, got %+v", findMap)
	}

	// 6. GET /v1/assets?target=...
	reqAssets := httptest.NewRequest(http.MethodGet, "/v1/assets?target="+targetHost, nil)
	recAssets := httptest.NewRecorder()
	srv.ServeHTTP(recAssets, reqAssets)
	if recAssets.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/assets, got %d", recAssets.Code)
	}
	var assetsMap map[string]interface{}
	_ = json.Unmarshal(recAssets.Body.Bytes(), &assetsMap)
	if assetsMap["total"].(float64) < 1 {
		t.Errorf("expected at least 1 asset, got %+v", assetsMap)
	}

	// 7. GET /v1/graph?target=...
	reqGraph := httptest.NewRequest(http.MethodGet, "/v1/graph?target="+targetHost, nil)
	recGraph := httptest.NewRecorder()
	srv.ServeHTTP(recGraph, reqGraph)
	if recGraph.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/graph, got %d", recGraph.Code)
	}
	var graphMap cytoscapeGraph
	_ = json.Unmarshal(recGraph.Body.Bytes(), &graphMap)
	if len(graphMap.Elements.Nodes) < 2 {
		t.Errorf("expected nodes in graph elements, got %+v", graphMap)
	}
}

func TestEndpoints_Diff(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	defer store.Close()

	onion := "difftest.onion"
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	scan1 := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(-10 * time.Minute),
		EndedAt:   now.Add(-5 * time.Minute),
		RiskScore: 30,
	}
	id1, _ := store.Save(scan1)

	scan2 := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(-2 * time.Minute),
		EndedAt:   now,
		RiskScore: 50,
	}
	id2, _ := store.Save(scan2)

	req := httptest.NewRequest(http.MethodGet, "/v1/diff?target="+onion+"&old_scan="+id1+"&new_scan="+id2, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/diff, got %d: %s", rec.Code, rec.Body.String())
	}

	var d diff.DiffResult
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("failed to decode diff: %v", err)
	}
	if d.ScoreDelta != 20 {
		t.Errorf("expected score delta 20, got %d", d.ScoreDelta)
	}
}

func TestCreateScan_TargetValidation(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	defer store.Close()

	invalidTargets := []string{
		"",
		"   ",
		"../../escaping",
		"../target.onion",
		"target.onion/path",
		"target.onion\\path",
		"google.com",
		"https://evil.org",
		"target..onion",
		"-badhost.onion",
	}

	for _, target := range invalidTargets {
		body, _ := json.Marshal(map[string]interface{}{
			"target": target,
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/scans", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for target %q, got %d: %s", target, rec.Code, rec.Body.String())
		}
	}
}
