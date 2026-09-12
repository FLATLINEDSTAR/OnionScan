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

func TestJSONSchemaFieldNames_TargetsAndDiff(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	defer store.Close()

	onion := "schematest.onion"
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

	f1 := model.Finding{ID: "RULE-001", Title: "Old Resolved Finding", Severity: model.SeverityLow}
	f2Old := model.Finding{ID: "RULE-002", Title: "Persisting Finding", Severity: model.SeverityLow, Confidence: 0.5}
	f2New := model.Finding{ID: "RULE-002", Title: "Persisting Finding", Severity: model.SeverityHigh, Confidence: 0.9}
	f3 := model.Finding{ID: "RULE-003", Title: "Newly Introduced Finding", Severity: model.SeverityCritical}

	scan1 := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now,
		EndedAt:   now.Add(1 * time.Minute),
		RiskScore: 25,
		Findings:  []model.Finding{f1, f2Old},
	}
	id1, err := store.Save(scan1)
	if err != nil {
		t.Fatalf("save scan1 failed: %v", err)
	}

	scan2 := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(10 * time.Minute),
		EndedAt:   now.Add(11 * time.Minute),
		RiskScore: 60,
		Findings:  []model.Finding{f2New, f3},
	}
	id2, err := store.Save(scan2)
	if err != nil {
		t.Fatalf("save scan2 failed: %v", err)
	}

	// 1. Verify GET /v1/targets JSON schema
	reqTargets := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	recTargets := httptest.NewRecorder()
	srv.ServeHTTP(recTargets, reqTargets)
	if recTargets.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/targets, got %d", recTargets.Code)
	}

	var targetsRaw map[string]interface{}
	if err := json.Unmarshal(recTargets.Body.Bytes(), &targetsRaw); err != nil {
		t.Fatalf("failed to decode targets JSON: %v", err)
	}

	if targetsRaw["total"] == nil || targetsRaw["total"].(float64) < 1 {
		t.Errorf("expected non-zero total in targets response, got %v", targetsRaw["total"])
	}

	rawList, ok := targetsRaw["targets"].([]interface{})
	if !ok || len(rawList) == 0 {
		t.Fatalf("expected non-empty targets array, got %+v", targetsRaw)
	}
	tItem := rawList[0].(map[string]interface{})

	// Assert both Go and TypeScript expected field names are present and matching
	if tItem["target"] != onion {
		t.Errorf("expected target %q, got %v", onion, tItem["target"])
	}
	if tItem["onion"] != onion {
		t.Errorf("expected onion %q, got %v", onion, tItem["onion"])
	}
	if tItem["scan_count"].(float64) != 2 {
		t.Errorf("expected scan_count 2, got %v", tItem["scan_count"])
	}
	if tItem["total_scans"].(float64) != 2 {
		t.Errorf("expected total_scans 2, got %v", tItem["total_scans"])
	}
	if tItem["latest_scan_at"] == nil || tItem["latest_scan_at"] == "" {
		t.Errorf("expected latest_scan_at timestamp, got %v", tItem["latest_scan_at"])
	}
	if tItem["last_scanned_at"] == nil || tItem["last_scanned_at"] == "" {
		t.Errorf("expected last_scanned_at timestamp, got %v", tItem["last_scanned_at"])
	}
	if tItem["latest_risk_score"].(float64) != 60 {
		t.Errorf("expected latest_risk_score 60, got %v", tItem["latest_risk_score"])
	}
	if tItem["latest_findings_count"].(float64) != 2 {
		t.Errorf("expected latest_findings_count 2, got %v", tItem["latest_findings_count"])
	}

	// 2. Verify GET /v1/diff JSON schema
	reqDiff := httptest.NewRequest(http.MethodGet, "/v1/diff?target="+onion+"&old_scan="+id1+"&new_scan="+id2, nil)
	recDiff := httptest.NewRecorder()
	srv.ServeHTTP(recDiff, reqDiff)
	if recDiff.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/diff, got %d: %s", recDiff.Code, recDiff.Body.String())
	}

	var diffRaw map[string]interface{}
	if err := json.Unmarshal(recDiff.Body.Bytes(), &diffRaw); err != nil {
		t.Fatalf("failed to decode diff JSON: %v", err)
	}

	// Assert diff schema aliases
	if diffRaw["target"] != onion {
		t.Errorf("expected target %q, got %v", onion, diffRaw["target"])
	}
	if diffRaw["old_scan"] != id1 || diffRaw["old_scan_id"] != id1 {
		t.Errorf("expected old_scan and old_scan_id %q, got %v and %v", id1, diffRaw["old_scan"], diffRaw["old_scan_id"])
	}
	if diffRaw["new_scan"] != id2 || diffRaw["new_scan_id"] != id2 {
		t.Errorf("expected new_scan and new_scan_id %q, got %v and %v", id2, diffRaw["new_scan"], diffRaw["new_scan_id"])
	}
	if diffRaw["risk_score_delta"].(float64) != 35 || diffRaw["score_delta"].(float64) != 35 {
		t.Errorf("expected risk_score_delta and score_delta 35, got %v and %v", diffRaw["risk_score_delta"], diffRaw["score_delta"])
	}

	newFindings := diffRaw["new_findings"].([]interface{})
	if len(newFindings) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(newFindings))
	}

	resolvedFindings := diffRaw["resolved_findings"].([]interface{})
	removedFindings := diffRaw["removed_findings"].([]interface{})
	if len(resolvedFindings) != 1 || len(removedFindings) != 1 {
		t.Errorf("expected 1 resolved/removed finding, got %d and %d", len(resolvedFindings), len(removedFindings))
	}

	persistingFindings := diffRaw["persisting_findings"].([]interface{})
	if len(persistingFindings) != 1 {
		t.Errorf("expected 1 persisting finding, got %d", len(persistingFindings))
	}

	// 3. Test alias query parameters for /v1/diff
	reqDiffAliases := httptest.NewRequest(http.MethodGet, "/v1/diff?target="+onion+"&old_scan_id="+id1+"&new_scan_id="+id2, nil)
	recDiffAliases := httptest.NewRecorder()
	srv.ServeHTTP(recDiffAliases, reqDiffAliases)
	if recDiffAliases.Code != http.StatusOK {
		t.Fatalf("expected 200 for /v1/diff with aliases, got %d", recDiffAliases.Code)
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

func TestAsyncScan_ConcurrencyLimitsAndQueue(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	defer store.Close()

	srv.MaxConcurrentScans = 2
	srv.MaxQueueSize = 2

	// Channel to control test server responses
	proceed := make(chan struct{})
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-proceed // block until signaled
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Hello</body></html>`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	srv.TorClient = ts.Client()

	// 1. Submit 2 scans -> both should start running immediately (MaxConcurrentScans = 2)
	postScan := func() (int, map[string]interface{}) {
		body, _ := json.Marshal(map[string]interface{}{
			"target": u.Host,
			"async":  true,
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/scans", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		var resp map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec.Code, resp
	}

	code1, resp1 := postScan()
	code2, resp2 := postScan()

	if code1 != http.StatusAccepted || code2 != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for first 2 scans, got %d and %d", code1, code2)
	}

	id1 := resp1["id"].(string)
	id2 := resp2["id"].(string)

	if resp1["status"] != "running" || resp2["status"] != "running" {
		t.Errorf("expected both initial scans to be running, got %v and %v", resp1["status"], resp2["status"])
	}

	if active := srv.ActiveScans(); active != 2 {
		t.Fatalf("expected 2 active scans, got %d", active)
	}

	// 2. Submit 2 more scans -> should be queued (MaxQueueSize = 2)
	code3, resp3 := postScan()
	code4, resp4 := postScan()

	if code3 != http.StatusAccepted || code4 != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for queued scans, got %d and %d", code3, code4)
	}

	id3 := resp3["id"].(string)
	id4 := resp4["id"].(string)

	if resp3["status"] != "queued" || resp4["status"] != "queued" {
		t.Errorf("expected 3rd and 4th scans to be queued, got %v and %v", resp3["status"], resp4["status"])
	}

	if queued := srv.QueuedScans(); queued != 2 {
		t.Fatalf("expected 2 queued scans, got %d", queued)
	}

	// 3. Submit 5th scan -> queue capacity exceeded, should return 429 Too Many Requests
	code5, resp5 := postScan()
	if code5 != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests for 5th scan, got %d: %+v", code5, resp5)
	}
	errObj, _ := resp5["error"].(map[string]interface{})
	if errObj["code"] != "TOO_MANY_REQUESTS" {
		t.Errorf("expected error code TOO_MANY_REQUESTS, got %v", errObj["code"])
	}

	// 4. Verify querying GET /v1/scans/{id} reports status accurately
	getScanStatus := func(id string) string {
		req := httptest.NewRequest(http.MethodGet, "/v1/scans/"+id, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for GET /v1/scans/%s, got %d: %s", id, rec.Code, rec.Body.String())
		}
		var r map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return r["status"].(string)
	}

	if st := getScanStatus(id1); st != "running" {
		t.Errorf("expected scan %s status running, got %s", id1, st)
	}
	if st := getScanStatus(id3); st != "queued" {
		t.Errorf("expected scan %s status queued, got %s", id3, st)
	}

	// 5. Release blocked HTTP requests to let scans complete
	close(proceed)

	// Wait for all 4 scans to complete
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ActiveScans() == 0 && srv.QueuedScans() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if active := srv.ActiveScans(); active != 0 {
		t.Errorf("expected 0 active scans after completion, got %d", active)
	}
	if queued := srv.QueuedScans(); queued != 0 {
		t.Errorf("expected 0 queued scans after completion, got %d", queued)
	}

	// 6. Verify completed scans via GET /v1/scans/{id}
	for _, id := range []string{id1, id2, id3, id4} {
		st := getScanStatus(id)
		if st != "completed" {
			t.Errorf("expected scan %s status completed, got %s", id, st)
		}
	}
}

func TestAsyncScan_FailedScanStatus(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	// Close store so scan.Run fails when attempting to persist the result
	_ = store.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Hello</body></html>`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	srv.TorClient = ts.Client()

	body, _ := json.Marshal(map[string]interface{}{
		"target": u.Host,
		"async":  true,
		"limits": map[string]interface{}{
			"page_timeout": "100ms",
			"total_budget": "500ms",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", rec.Code)
	}

	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id := resp["id"].(string)

	// Wait for job to fail
	deadline := time.Now().Add(3 * time.Second)
	var finalStatus string
	for time.Now().Before(deadline) {
		job, ok := srv.GetJob(id)
		if ok && (job.Status == ScanStatusFailed || job.Status == ScanStatusCompleted) {
			finalStatus = string(job.Status)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if finalStatus != "failed" {
		t.Fatalf("expected scan to fail, got %s", finalStatus)
	}

	// Verify GET /v1/scans/{id} returns status "failed" and error message
	reqGet := httptest.NewRequest(http.MethodGet, "/v1/scans/"+id, nil)
	recGet := httptest.NewRecorder()
	srv.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET failed scan, got %d", recGet.Code)
	}
	var getResp map[string]interface{}
	_ = json.Unmarshal(recGet.Body.Bytes(), &getResp)
	if getResp["status"] != "failed" {
		t.Errorf("expected status failed, got %v", getResp["status"])
	}
	if getResp["error"] == nil || getResp["error"] == "" {
		t.Errorf("expected non-empty error message, got %v", getResp["error"])
	}
}
