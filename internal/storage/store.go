// Package storage persists scan history and an inverted evidence index so
// `onionsec monitor` can diff runs and the correlation engine can perform
// fast cross-target correlation.
//
// The MVP uses one JSON file per scan on disk plus an inverted index under
// .evidence_index/ to avoid a cgo/SQLite dependency; see issue "Phase 4: migrate storage to
// SQLite" for the upgrade path once monitoring needs real querying.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// TargetLink represents an association between an evidence item and a target.
type TargetLink struct {
	Onion      string    `json:"onion"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastScanID string    `json:"last_scan_id"`
	Sources    []string  `json:"sources"`
}

// EvidenceEntry models a canonical evidence item and all targets associated with it.
type EvidenceEntry struct {
	Type             model.EvidenceType `json:"type"`
	CanonicalValue   string             `json:"canonical_value"`
	ValueHash        string             `json:"value_hash"`
	FirstSeen        time.Time          `json:"first_seen"`
	LastSeen         time.Time          `json:"last_seen"`
	TotalOccurrences int                `json:"total_occurrences"`
	Targets          []TargetLink       `json:"targets"`
}

// Store reads/writes scan results under a base directory, one subfolder
// per target (sanitized) and one JSON file per scan timestamp.
type Store struct {
	BaseDir string
	mu      sync.Mutex
}

func New(baseDir string) *Store {
	return &Store{BaseDir: baseDir}
}

func (s *Store) targetDir(onion string) string {
	safe := strings.NewReplacer("/", "_", ":", "_").Replace(onion)
	return filepath.Join(s.BaseDir, safe)
}

func (s *Store) indexDir(evType model.EvidenceType) string {
	return filepath.Join(s.BaseDir, ".evidence_index", string(evType))
}

// Save writes a scan result, indexes its evidence, and returns the file path it was written to.
func (s *Store) Save(result model.ScanResult) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.targetDir(result.Target.Onion)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create scan dir: %w", err)
	}
	scanID := result.EndedAt.UTC().Format("20060102T150405Z")
	name := scanID + ".json"
	path := filepath.Join(dir, name)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create scan file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return "", fmt.Errorf("write scan file: %w", err)
	}

	// Maintain the inverted evidence index
	_ = s.indexEvidenceLocked(result, scanID)

	return path, nil
}

// History returns every past scan for a target, oldest first.
func (s *Store) History(onion string) ([]model.ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.targetDir(onion)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // filenames are timestamp-prefixed, so lexical == chronological

	var results []model.ScanResult
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var r model.ScanResult
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

// Latest returns the most recent scan for a target, or ok=false if none exist.
func (s *Store) Latest(onion string) (result model.ScanResult, ok bool, err error) {
	hist, err := s.History(onion)
	if err != nil || len(hist) == 0 {
		return model.ScanResult{}, false, err
	}
	return hist[len(hist)-1], true, nil
}

// Targets returns a list of all onion targets currently recorded in the store.
func (s *Store) Targets() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.BaseDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var targets []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			targets = append(targets, e.Name())
		}
	}
	sort.Strings(targets)
	return targets, nil
}

// IndexEvidence records all evidence facts from a scan into the inverted evidence store.
func (s *Store) IndexEvidence(result model.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	scanID := result.EndedAt.UTC().Format("20060102T150405Z")
	return s.indexEvidenceLocked(result, scanID)
}

func (s *Store) indexEvidenceLocked(result model.ScanResult, scanID string) error {
	for _, f := range result.Findings {
		for _, ev := range f.Evidence {
			// Safety: never index raw credentials
			if ev.Type == model.EvidenceCredential {
				continue
			}

			val := strings.TrimSpace(ev.Description)
			if val == "" {
				continue
			}

			canon := CanonicalizeValue(ev.Type, val)
			hash := ValueHash(ev.Type, canon)

			dir := s.indexDir(ev.Type)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}

			indexPath := filepath.Join(dir, hash+".json")
			var entry EvidenceEntry

			data, err := os.ReadFile(indexPath)
			if err == nil {
				_ = json.Unmarshal(data, &entry)
			}

			if entry.CanonicalValue == "" {
				entry.Type = ev.Type
				entry.CanonicalValue = canon
				entry.ValueHash = hash
				entry.FirstSeen = result.StartedAt
			}

			entry.LastSeen = result.EndedAt
			entry.TotalOccurrences++

			// Update target links
			targetOnion := result.Target.Onion
			targetIdx := -1
			for i, t := range entry.Targets {
				if t.Onion == targetOnion {
					targetIdx = i
					break
				}
			}

			if targetIdx >= 0 {
				entry.Targets[targetIdx].LastSeen = result.EndedAt
				entry.Targets[targetIdx].LastScanID = scanID
				if ev.Source != "" {
					entry.Targets[targetIdx].Sources = dedupeStrings(append(entry.Targets[targetIdx].Sources, ev.Source))
				}
			} else {
				var sources []string
				if ev.Source != "" {
					sources = []string{ev.Source}
				}
				entry.Targets = append(entry.Targets, TargetLink{
					Onion:      targetOnion,
					FirstSeen:  result.StartedAt,
					LastSeen:   result.EndedAt,
					LastScanID: scanID,
					Sources:    sources,
				})
			}

			// Atomic write
			tmpPath := indexPath + ".tmp"
			f, err := os.Create(tmpPath)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(entry); err != nil {
				f.Close()
				_ = os.Remove(tmpPath)
				return err
			}
			f.Close()
			_ = os.Rename(tmpPath, indexPath)
		}
	}
	return nil
}

// FindCoOccurringTargets looks up which targets have ever exhibited an evidence item.
func (s *Store) FindCoOccurringTargets(evType model.EvidenceType, rawVal string) ([]TargetLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	canon := CanonicalizeValue(evType, rawVal)
	hash := ValueHash(evType, canon)
	indexPath := filepath.Join(s.indexDir(evType), hash+".json")

	data, err := os.ReadFile(indexPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var entry EvidenceEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return entry.Targets, nil
}

// CanonicalizeValue standardizes evidence representation across casing and formats.
func CanonicalizeValue(evType model.EvidenceType, raw string) string {
	trimmed := strings.TrimSpace(raw)
	switch evType {
	case model.EvidenceIP:
		host, _, err := net.SplitHostPort(trimmed)
		if err == nil {
			trimmed = host
		}
		if ip := net.ParseIP(trimmed); ip != nil {
			return ip.String()
		}
		return strings.ToLower(trimmed)
	case model.EvidenceHostname, model.EvidenceEmail:
		trimmed = strings.TrimPrefix(trimmed, "mailto:")
		trimmed = strings.TrimRight(trimmed, ".")
		return strings.ToLower(trimmed)
	case model.EvidenceTLS, model.EvidenceFingerprint:
		cleaned := strings.ToLower(trimmed)
		cleaned = strings.ReplaceAll(cleaned, ":", "")
		cleaned = strings.ReplaceAll(cleaned, " ", "")
		return cleaned
	default:
		return strings.ToLower(trimmed)
	}
}

// ValueHash returns the SHA-256 hex digest for an evidence item.
func ValueHash(evType model.EvidenceType, canonicalVal string) string {
	h := sha256.Sum256([]byte(string(evType) + ":" + canonicalVal))
	return hex.EncodeToString(h[:])
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
