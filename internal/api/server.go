package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/crawler"
	"github.com/AryanXCode646/OnionScan/internal/diff"
	"github.com/AryanXCode646/OnionScan/internal/graph"
	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/scan"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

// ErrQueueFull is returned when the asynchronous scan queue capacity is exceeded.
var ErrQueueFull = errors.New("scan queue full")

// ScanStatus describes the lifecycle state of a scan job.
type ScanStatus string

const (
	ScanStatusQueued    ScanStatus = "queued"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

// ScanJob tracks the execution state and results for an asynchronous scan.
type ScanJob struct {
	ID        string            `json:"id"`
	Target    string            `json:"target"`
	Status    ScanStatus        `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
	StartedAt *time.Time        `json:"started_at,omitempty"`
	EndedAt   *time.Time        `json:"ended_at,omitempty"`
	Error     string            `json:"error,omitempty"`
	Result    *model.ScanResult `json:"result,omitempty"`

	limits crawler.Limits
	cancel context.CancelFunc
}

// Server provides the HTTP REST API server for OnionSec.
type Server struct {
	Store              storage.Store
	TorClient          *http.Client
	Limits             crawler.Limits
	AuthToken          string
	MaxConcurrentScans int
	MaxQueueSize       int

	mux         *http.ServeMux
	mu          sync.Mutex
	activeScans int
	queuedJobs  []*ScanJob
	jobs        map[string]*ScanJob
}

// NewServer initializes an API Server with all registered endpoints.
func NewServer(store storage.Store, torClient *http.Client, limits crawler.Limits, authToken string) *Server {
	s := &Server{
		Store:              store,
		TorClient:          torClient,
		Limits:             limits,
		AuthToken:          authToken,
		MaxConcurrentScans: 4,
		MaxQueueSize:       32,
		mux:                http.NewServeMux(),
		jobs:               make(map[string]*ScanJob),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /v1/health", s.handleHealthz)
	s.mux.HandleFunc("GET /v1/targets", s.requireAuth(s.handleGetTargets))
	s.mux.HandleFunc("POST /v1/scans", s.requireAuth(s.handleCreateScan))
	s.mux.HandleFunc("GET /v1/scans/{id}", s.requireAuth(s.handleGetScan))
	s.mux.HandleFunc("GET /v1/findings", s.requireAuth(s.handleGetFindings))
	s.mux.HandleFunc("GET /v1/assets", s.requireAuth(s.handleGetAssets))
	s.mux.HandleFunc("GET /v1/history", s.requireAuth(s.handleGetHistory))
	s.mux.HandleFunc("GET /v1/graph", s.requireAuth(s.handleGetGraph))
	s.mux.HandleFunc("GET /v1/diff", s.requireAuth(s.handleGetDiff))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS Headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	s.mux.ServeHTTP(w, r)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AuthToken != "" {
			authHeader := r.Header.Get("Authorization")
			apiKey := r.Header.Get("X-API-Key")
			token := ""
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			} else if apiKey != "" {
				token = apiKey
			}

			if token == "" || token != s.AuthToken {
				writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or missing authorization credentials")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"version": "0.1.0-dev",
		"storage": "connected",
	})
}

type targetSummary struct {
	Onion           string    `json:"onion"`
	FirstScannedAt  time.Time `json:"first_scanned_at"`
	LastScannedAt   time.Time `json:"last_scanned_at"`
	TotalScans      int       `json:"total_scans"`
	LatestRiskScore int       `json:"latest_risk_score"`
}

func (s *Server) handleGetTargets(w http.ResponseWriter, r *http.Request) {
	targetList, err := s.Store.Targets()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
		return
	}

	var summaries []targetSummary
	for _, onion := range targetList {
		hist, err := s.Store.History(onion)
		if err != nil || len(hist) == 0 {
			continue
		}
		latest := hist[len(hist)-1]
		summaries = append(summaries, targetSummary{
			Onion:           onion,
			FirstScannedAt:  hist[0].StartedAt,
			LastScannedAt:   latest.EndedAt,
			TotalScans:      len(hist),
			LatestRiskScore: latest.RiskScore,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"targets": summaries,
	})
}

type scanRequest struct {
	Target string         `json:"target"`
	Async  bool           `json:"async"`
	Limits *crawlerLimits `json:"limits"`
}

type crawlerLimits struct {
	MaxPages    int    `json:"max_pages"`
	MaxBodyByte int64  `json:"max_body_byte"`
	PageTimeout string `json:"page_timeout"`
	TotalBudget string `json:"total_budget"`
}

type scanCreatedResponse struct {
	ID            string          `json:"id"`
	Target        string          `json:"target"`
	Status        string          `json:"status"`
	StartedAt     time.Time       `json:"started_at"`
	EndedAt       time.Time       `json:"ended_at"`
	PagesSeen     int             `json:"pages_seen"`
	RiskScore     int             `json:"risk_score"`
	FindingsCount int             `json:"findings_count"`
	Findings      []model.Finding `json:"findings"`
}

// ActiveScans returns the count of currently running scans.
func (s *Server) ActiveScans() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeScans
}

// QueuedScans returns the count of currently queued scans.
func (s *Server) QueuedScans() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queuedJobs)
}

// GetJob returns a copy of the scan job by ID if tracked in memory.
func (s *Server) GetJob(id string) (*ScanJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	jobCopy := *job
	return &jobCopy, true
}

func (s *Server) enqueueAsyncScan(scanID, target string, limits crawler.Limits) (*ScanJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	maxConcurrent := s.MaxConcurrentScans
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	maxQueue := s.MaxQueueSize
	if maxQueue <= 0 {
		maxQueue = 32
	}

	if len(s.queuedJobs) >= maxQueue {
		return nil, ErrQueueFull
	}

	if _, exists := s.jobs[scanID]; exists {
		scanID = fmt.Sprintf("%s-%d", scanID, time.Now().UnixNano()%10000)
	}

	now := time.Now().UTC()
	job := &ScanJob{
		ID:        scanID,
		Target:    target,
		Status:    ScanStatusQueued,
		CreatedAt: now,
		limits:    limits,
	}

	s.pruneJobsLocked()
	s.jobs[scanID] = job

	if s.activeScans < maxConcurrent {
		s.activeScans++
		job.Status = ScanStatusRunning
		startedAt := time.Now().UTC()
		job.StartedAt = &startedAt
		go s.executeJob(job)
	} else {
		s.queuedJobs = append(s.queuedJobs, job)
	}

	jobCopy := *job
	return &jobCopy, nil
}

func (s *Server) executeJob(job *ScanJob) {
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			endedAt := time.Now().UTC()
			job.EndedAt = &endedAt
			job.Status = ScanStatusFailed
			job.Error = fmt.Sprintf("panic: %v", r)
			s.dispatchNextLocked()
			s.mu.Unlock()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), job.limits.TotalBudget+time.Minute)
	s.mu.Lock()
	job.cancel = cancel
	s.mu.Unlock()
	defer cancel()

	target := model.Target{Onion: job.Target, CreatedAt: time.Now()}
	result, err := scan.Run(ctx, s.TorClient, s.Store, target, job.limits)

	s.mu.Lock()
	endedAt := time.Now().UTC()
	job.EndedAt = &endedAt
	if err != nil {
		job.Status = ScanStatusFailed
		job.Error = err.Error()
	} else {
		job.Status = ScanStatusCompleted
		job.Result = &result
	}

	s.dispatchNextLocked()
	s.mu.Unlock()
}

func (s *Server) dispatchNextLocked() {
	if len(s.queuedJobs) > 0 {
		nextJob := s.queuedJobs[0]
		s.queuedJobs = s.queuedJobs[1:]
		nextJob.Status = ScanStatusRunning
		startedAt := time.Now().UTC()
		nextJob.StartedAt = &startedAt
		go s.executeJob(nextJob)
	} else {
		s.activeScans--
	}
}

func (s *Server) pruneJobsLocked() {
	if len(s.jobs) <= 500 {
		return
	}
	for id, j := range s.jobs {
		if j.Status == ScanStatusCompleted || j.Status == ScanStatusFailed {
			delete(s.jobs, id)
			if len(s.jobs) <= 400 {
				break
			}
		}
	}
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON request body")
		return
	}

	target, err := model.ValidateOnion(req.Target)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_TARGET", fmt.Sprintf("Invalid target onion address: %v", err))
		return
	}

	limits := s.Limits
	if req.Limits != nil {
		if req.Limits.MaxPages > 0 {
			limits.MaxPages = req.Limits.MaxPages
		}
		if req.Limits.MaxBodyByte > 0 {
			limits.MaxBodyByte = req.Limits.MaxBodyByte
		}
		if req.Limits.PageTimeout != "" {
			if d, err := time.ParseDuration(req.Limits.PageTimeout); err == nil {
				limits.PageTimeout = d
			}
		}
		if req.Limits.TotalBudget != "" {
			if d, err := time.ParseDuration(req.Limits.TotalBudget); err == nil {
				limits.TotalBudget = d
			}
		}
	}

	if req.Async {
		scanID := time.Now().UTC().Format("20060102T150405Z")
		job, err := s.enqueueAsyncScan(scanID, target, limits)
		if err != nil {
			if errors.Is(err, ErrQueueFull) {
				writeJSONError(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Scan queue capacity exceeded. Please retry later.")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "QUEUE_ERROR", err.Error())
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"id":         job.ID,
			"target":     job.Target,
			"status":     string(job.Status),
			"status_url": fmt.Sprintf("/v1/scans/%s?target=%s", job.ID, job.Target),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), limits.TotalBudget+time.Minute)
	defer cancel()

	result, err := scan.Run(ctx, s.TorClient, s.Store, model.Target{Onion: target, CreatedAt: time.Now()}, limits)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "SCAN_FAILED", err.Error())
		return
	}

	scanID := result.EndedAt.UTC().Format("20060102T150405Z")
	s.mu.Lock()
	s.pruneJobsLocked()
	s.jobs[scanID] = &ScanJob{
		ID:        scanID,
		Target:    target,
		Status:    ScanStatusCompleted,
		CreatedAt: result.StartedAt,
		StartedAt: &result.StartedAt,
		EndedAt:   &result.EndedAt,
		Result:    &result,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusCreated, scanCreatedResponse{
		ID:            scanID,
		Target:        target,
		Status:        "completed",
		StartedAt:     result.StartedAt,
		EndedAt:       result.EndedAt,
		PagesSeen:     result.PagesSeen,
		RiskScore:     result.RiskScore,
		FindingsCount: len(result.Findings),
		Findings:      result.Findings,
	})
}

type scanResponse struct {
	model.ScanResult
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	target := r.URL.Query().Get("target")

	// Check in-memory jobs first
	s.mu.Lock()
	job, jobFound := s.jobs[scanID]
	var jobCopy ScanJob
	if jobFound {
		jobCopy = *job
	}
	s.mu.Unlock()

	if jobFound {
		if jobCopy.Status == ScanStatusQueued || jobCopy.Status == ScanStatusRunning {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"id":         jobCopy.ID,
				"target":     jobCopy.Target,
				"status":     string(jobCopy.Status),
				"created_at": jobCopy.CreatedAt,
				"started_at": jobCopy.StartedAt,
			})
			return
		}

		if jobCopy.Status == ScanStatusFailed {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"id":         jobCopy.ID,
				"target":     jobCopy.Target,
				"status":     string(jobCopy.Status),
				"created_at": jobCopy.CreatedAt,
				"started_at": jobCopy.StartedAt,
				"ended_at":   jobCopy.EndedAt,
				"error":      jobCopy.Error,
			})
			return
		}

		if jobCopy.Status == ScanStatusCompleted {
			if s.Store != nil {
				res, ok, err := s.Store.GetScan(jobCopy.Target, scanID)
				if err == nil && ok {
					writeJSON(w, http.StatusOK, scanResponse{
						ScanResult: res,
						ID:         scanID,
						Status:     "completed",
					})
					return
				}
			}
			if jobCopy.Result != nil {
				writeJSON(w, http.StatusOK, scanResponse{
					ScanResult: *jobCopy.Result,
					ID:         scanID,
					Status:     "completed",
				})
				return
			}
		}
	}

	if target != "" {
		if s.Store != nil {
			res, ok, err := s.Store.GetScan(target, scanID)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
				return
			}
			if ok {
				writeJSON(w, http.StatusOK, scanResponse{
					ScanResult: res,
					ID:         scanID,
					Status:     "completed",
				})
				return
			}
		}
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Scan %q not found for target %q", scanID, target))
		return
	}

	// Search across targets if target not explicitly passed
	if s.Store != nil {
		targets, err := s.Store.Targets()
		if err == nil {
			for _, t := range targets {
				res, ok, err := s.Store.GetScan(t, scanID)
				if err == nil && ok {
					writeJSON(w, http.StatusOK, scanResponse{
						ScanResult: res,
						ID:         scanID,
						Status:     "completed",
					})
					return
				}
			}
		}
	}

	writeJSONError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Scan %q not found", scanID))
}

func (s *Server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	severityFilter := strings.ToUpper(r.URL.Query().Get("severity"))
	analyzerFilter := strings.ToLower(r.URL.Query().Get("analyzer"))

	var allFindings []model.Finding

	if target != "" {
		latest, ok, err := s.Store.Latest(target)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
			return
		}
		if ok {
			allFindings = append(allFindings, latest.Findings...)
		}
	} else {
		targets, err := s.Store.Targets()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
			return
		}
		for _, t := range targets {
			latest, ok, err := s.Store.Latest(t)
			if err == nil && ok {
				allFindings = append(allFindings, latest.Findings...)
			}
		}
	}

	var filtered []model.Finding
	for _, f := range allFindings {
		if severityFilter != "" && string(f.Severity) != severityFilter {
			continue
		}
		if analyzerFilter != "" && strings.ToLower(f.Analyzer) != analyzerFilter {
			continue
		}
		filtered = append(filtered, f)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":   target,
		"total":    len(filtered),
		"findings": filtered,
	})
}

func (s *Server) handleGetAssets(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	evType := model.EvidenceType(r.URL.Query().Get("type"))

	assets, err := s.Store.ListAssets(target, evType)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":  len(assets),
		"assets": assets,
	})
}

type historyItem struct {
	ScanID        string    `json:"scan_id"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at"`
	PagesSeen     int       `json:"pages_seen"`
	RiskScore     int       `json:"risk_score"`
	FindingsCount int       `json:"findings_count"`
}

func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_TARGET", "Target query parameter is required")
		return
	}

	limit := 50
	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		if val, err := strconv.Atoi(limStr); err == nil && val > 0 {
			limit = val
		}
	}

	scans, err := s.Store.History(target)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
		return
	}

	var items []historyItem
	for _, s := range scans {
		items = append(items, historyItem{
			ScanID:        s.EndedAt.UTC().Format("20060102T150405Z"),
			StartedAt:     s.StartedAt,
			EndedAt:       s.EndedAt,
			PagesSeen:     s.PagesSeen,
			RiskScore:     s.RiskScore,
			FindingsCount: len(s.Findings),
		})
	}

	if len(items) > limit {
		items = items[len(items)-limit:]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":  target,
		"history": items,
	})
}

type cytoscapeElement struct {
	Data map[string]interface{} `json:"data"`
}

type cytoscapeGraph struct {
	Target   string `json:"target"`
	Elements struct {
		Nodes []cytoscapeElement `json:"nodes"`
		Edges []cytoscapeElement `json:"edges"`
	} `json:"elements"`
}

func (s *Server) handleGetGraph(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_TARGET", "Target query parameter is required")
		return
	}

	g, err := graph.BuildGraph(target, s.Store)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "GRAPH_ERROR", err.Error())
		return
	}

	var resp cytoscapeGraph
	resp.Target = target

	// Target node
	resp.Elements.Nodes = append(resp.Elements.Nodes, cytoscapeElement{
		Data: map[string]interface{}{
			"id":    "target",
			"label": target,
			"type":  "target",
		},
	})

	for i, n := range g.Nodes {
		evID := fmt.Sprintf("ev_%d", i)
		resp.Elements.Nodes = append(resp.Elements.Nodes, cytoscapeElement{
			Data: map[string]interface{}{
				"id":    evID,
				"label": n.Value,
				"type":  string(n.Type),
			},
		})
		resp.Elements.Edges = append(resp.Elements.Edges, cytoscapeElement{
			Data: map[string]interface{}{
				"source": "target",
				"target": evID,
				"label":  "exhibits",
			},
		})

		for j, peer := range n.Peers {
			peerID := fmt.Sprintf("peer_%s", peer)
			peerExists := false
			for _, node := range resp.Elements.Nodes {
				if node.Data["id"] == peerID {
					peerExists = true
					break
				}
			}
			if !peerExists {
				resp.Elements.Nodes = append(resp.Elements.Nodes, cytoscapeElement{
					Data: map[string]interface{}{
						"id":    peerID,
						"label": peer,
						"type":  "peer",
					},
				})
			}
			resp.Elements.Edges = append(resp.Elements.Edges, cytoscapeElement{
				Data: map[string]interface{}{
					"id":     fmt.Sprintf("edge_%d_%d", i, j),
					"source": evID,
					"target": peerID,
					"label":  "co-occurs",
				},
			})
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetDiff(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	oldScanID := r.URL.Query().Get("old_scan")
	newScanID := r.URL.Query().Get("new_scan")

	if target == "" || oldScanID == "" || newScanID == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PARAM", "target, old_scan, and new_scan query parameters are required")
		return
	}

	scan1, ok1, err := s.Store.GetScan(target, oldScanID)
	if err != nil || !ok1 {
		writeJSONError(w, http.StatusNotFound, "SCAN_NOT_FOUND", fmt.Sprintf("Scan %q not found for target %q", oldScanID, target))
		return
	}

	scan2, ok2, err := s.Store.GetScan(target, newScanID)
	if err != nil || !ok2 {
		writeJSONError(w, http.StatusNotFound, "SCAN_NOT_FOUND", fmt.Sprintf("Scan %q not found for target %q", newScanID, target))
		return
	}

	d := diff.Diff(scan1, true, scan2)
	writeJSON(w, http.StatusOK, d)
}

type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error: errorDetail{
			Code:    code,
			Message: message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
