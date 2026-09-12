// Package storage persists scan history and relational evidence indexing
// using SQLite so `onionsec monitor` can diff runs and the correlation
// engine can perform fast cross-target queries.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
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

// AssetItem represents an indexed evidence asset and its observed target co-occurrences.
type AssetItem struct {
	Type               model.EvidenceType `json:"type"`
	CanonicalValue     string             `json:"canonical_value"`
	FirstSeen          time.Time          `json:"first_seen"`
	LastSeen           time.Time          `json:"last_seen"`
	CoOccurringTargets []string           `json:"co_occurring_targets"`
}

// Store abstracts the persistence layer for scan results and evidence indexing.
type Store interface {
	Save(result model.ScanResult) (string, error)
	History(onion string) ([]model.ScanResult, error)
	Latest(onion string) (model.ScanResult, bool, error)
	GetScan(onion string, scanID string) (model.ScanResult, bool, error)
	Targets() ([]string, error)
	IndexEvidence(result model.ScanResult) error
	FindCoOccurringTargets(evType model.EvidenceType, rawVal string) ([]TargetLink, error)
	ListAssets(target string, evType model.EvidenceType) ([]AssetItem, error)
	Close() error
}

// New opens a SQLite-backed Store (the default storage engine).
func New(target string) (*SQLiteStore, error) {
	return OpenSQLite(target)
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
