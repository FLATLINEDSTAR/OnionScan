package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// FileStore reads/writes scan results under a base directory, one subfolder
// per target (sanitized) and one JSON file per scan timestamp.
type FileStore struct {
	BaseDir string
	mu      sync.Mutex
}

// NewFileStore returns a legacy filesystem-backed Store.
func NewFileStore(baseDir string) *FileStore {
	return &FileStore{BaseDir: baseDir}
}

func (s *FileStore) Close() error {
	return nil
}

func (s *FileStore) targetDir(onion string) (string, error) {
	trimmed := strings.TrimSpace(onion)
	if trimmed == "" || strings.Contains(trimmed, "..") || trimmed == "." {
		return "", fmt.Errorf("invalid or traversing target path: %q", onion)
	}

	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(trimmed)
	safe = strings.Trim(safe, "_.")
	safe = strings.TrimSpace(safe)
	if safe == "" {
		return "", fmt.Errorf("invalid or traversing target path: %q", onion)
	}

	cleanBase := filepath.Clean(s.BaseDir)
	targetPath := filepath.Clean(filepath.Join(cleanBase, safe))
	rel, err := filepath.Rel(cleanBase, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return "", fmt.Errorf("target path %q traverses outside base directory %q", onion, s.BaseDir)
	}
	return targetPath, nil
}

func (s *FileStore) indexDir(evType model.EvidenceType) string {
	return filepath.Join(s.BaseDir, ".evidence_index", string(evType))
}

// Save writes a scan result, indexes its evidence, and returns the file path it was written to.
func (s *FileStore) Save(result model.ScanResult) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := s.targetDir(result.Target.Onion)
	if err != nil {
		return "", fmt.Errorf("target directory: %w", err)
	}
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
func (s *FileStore) History(onion string) ([]model.ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := s.targetDir(onion)
	if err != nil {
		return nil, fmt.Errorf("target directory: %w", err)
	}
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
	sort.Strings(names)

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
func (s *FileStore) Latest(onion string) (result model.ScanResult, ok bool, err error) {
	hist, err := s.History(onion)
	if err != nil || len(hist) == 0 {
		return model.ScanResult{}, false, err
	}
	return hist[len(hist)-1], true, nil
}

// GetScan returns a specific past scan by target onion and scan ID.
func (s *FileStore) GetScan(onion string, scanID string) (model.ScanResult, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := s.targetDir(onion)
	if err != nil {
		return model.ScanResult{}, false, fmt.Errorf("target directory: %w", err)
	}

	if !strings.HasSuffix(scanID, ".json") {
		scanID = scanID + ".json"
	}
	cleanScanID := filepath.Base(scanID)
	path := filepath.Join(dir, cleanScanID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return model.ScanResult{}, false, nil
	}
	if err != nil {
		return model.ScanResult{}, false, err
	}
	var r model.ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return model.ScanResult{}, false, err
	}
	return r, true, nil
}

// Targets returns a list of all onion targets currently recorded in the store.
func (s *FileStore) Targets() ([]string, error) {
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
func (s *FileStore) IndexEvidence(result model.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	scanID := result.EndedAt.UTC().Format("20060102T150405Z")
	return s.indexEvidenceLocked(result, scanID)
}

func (s *FileStore) indexEvidenceLocked(result model.ScanResult, scanID string) error {
	for _, f := range result.Findings {
		for _, ev := range f.Evidence {
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
func (s *FileStore) FindCoOccurringTargets(evType model.EvidenceType, rawVal string) ([]TargetLink, error) {
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

// ListAssets returns evidence items and their associated targets, optionally filtered by target and evidence type.
func (s *FileStore) ListAssets(target string, evType model.EvidenceType) ([]AssetItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var types []model.EvidenceType
	if evType != "" {
		types = []model.EvidenceType{evType}
	} else {
		types = []model.EvidenceType{
			model.EvidenceIP,
			model.EvidenceHostname,
			model.EvidenceTLS,
			model.EvidenceHTTPHeader,
			model.EvidenceFingerprint,
			model.EvidenceMetadata,
			model.EvidenceEmail,
			model.EvidenceExternalRes,
		}
	}

	var items []AssetItem
	for _, t := range types {
		dir := s.indexDir(t)
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}

		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			var entry EvidenceEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				continue
			}

			if target != "" {
				matched := false
				for _, link := range entry.Targets {
					if link.Onion == target {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			var peers []string
			for _, link := range entry.Targets {
				peers = append(peers, link.Onion)
			}

			items = append(items, AssetItem{
				Type:               entry.Type,
				CanonicalValue:     entry.CanonicalValue,
				FirstSeen:          entry.FirstSeen,
				LastSeen:           entry.LastSeen,
				CoOccurringTargets: dedupeStrings(peers),
			})
		}
	}

	return items, nil
}
