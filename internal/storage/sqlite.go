package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AryanXCode646/OnionScan/internal/model"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements Store using a SQLite database.
type SQLiteStore struct {
	db     *sql.DB
	dbPath string
}

// OpenSQLite opens or creates a SQLite-backed store at dbPath.
// If dbPath is ":memory:", an in-memory database is used.
func OpenSQLite(dbPath string) (*SQLiteStore, error) {
	var dsn string
	if dbPath == ":memory:" {
		dsn = "file::memory:?cache=shared&mode=memory"
	} else {
		// If given a directory path, use onionsec.db inside it
		if strings.HasSuffix(dbPath, string(filepath.Separator)) {
			dbPath = filepath.Join(dbPath, "onionsec.db")
		} else if info, err := os.Stat(dbPath); err == nil && info.IsDir() {
			dbPath = filepath.Join(dbPath, "onionsec.db")
		} else if !strings.HasSuffix(dbPath, ".db") && !strings.HasSuffix(dbPath, ".sqlite") {
			// If not ending in .db/.sqlite, treat as directory
			dbPath = filepath.Join(dbPath, "onionsec.db")
		}

		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}
		dsn = fmt.Sprintf("%s?_busy_timeout=5000&_journal_mode=WAL", dbPath)
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// SQLite only supports a single active writer at any time. Limit connection pool
	// to 1 to serialize transactions and prevent "database is locked" (SQLITE_BUSY) errors.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &SQLiteStore{
		db:     db,
		dbPath: dbPath,
	}

	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate sqlite schema: %w", err)
	}

	return store, nil
}

func (s *SQLiteStore) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		onion_address TEXT UNIQUE NOT NULL,
		first_scanned_at TIMESTAMP NOT NULL,
		last_scanned_at TIMESTAMP NOT NULL,
		total_scans INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS scans (
		id TEXT NOT NULL,
		target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
		started_at TIMESTAMP NOT NULL,
		ended_at TIMESTAMP NOT NULL,
		pages_seen INTEGER NOT NULL,
		risk_score INTEGER NOT NULL,
		raw_json TEXT NOT NULL,
		PRIMARY KEY (target_id, id)
	);

	CREATE INDEX IF NOT EXISTS idx_scans_target_ended ON scans(target_id, ended_at);

	CREATE TABLE IF NOT EXISTS evidence_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		evidence_type TEXT NOT NULL,
		canonical_value TEXT NOT NULL,
		value_hash TEXT NOT NULL,
		first_seen_at TIMESTAMP NOT NULL,
		last_seen_at TIMESTAMP NOT NULL,
		UNIQUE(evidence_type, value_hash)
	);

	CREATE INDEX IF NOT EXISTS idx_evidence_type_hash ON evidence_items(evidence_type, value_hash);

	CREATE TABLE IF NOT EXISTS target_evidence (
		target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
		evidence_id INTEGER NOT NULL REFERENCES evidence_items(id) ON DELETE CASCADE,
		first_seen_at TIMESTAMP NOT NULL,
		last_seen_at TIMESTAMP NOT NULL,
		last_scan_id TEXT NOT NULL,
		source_url TEXT,
		observation_count INTEGER DEFAULT 1,
		PRIMARY KEY(target_id, evidence_id)
	);

	CREATE INDEX IF NOT EXISTS idx_target_evidence_evidence ON target_evidence(evidence_id);
	CREATE INDEX IF NOT EXISTS idx_target_evidence_target ON target_evidence(target_id);
	`
	_, err := s.db.Exec(schema)
	return err
}

// Close closes the underlying SQLite database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// DBPath returns the file path of the database.
func (s *SQLiteStore) DBPath() string {
	return s.dbPath
}

// Save writes a scan result and returns the scan identifier.
func (s *SQLiteStore) Save(result model.ScanResult) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	scanID := result.EndedAt.UTC().Format("20060102T150405Z")

	// 1. Ensure target exists
	_, err = tx.Exec(`
		INSERT INTO targets (onion_address, first_scanned_at, last_scanned_at, total_scans)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(onion_address) DO UPDATE SET
			last_scanned_at = excluded.last_scanned_at,
			total_scans = total_scans + 1;
	`, result.Target.Onion, result.StartedAt, result.EndedAt)
	if err != nil {
		return "", fmt.Errorf("upsert target: %w", err)
	}

	var targetID int64
	err = tx.QueryRow(`SELECT id FROM targets WHERE onion_address = ?`, result.Target.Onion).Scan(&targetID)
	if err != nil {
		return "", fmt.Errorf("lookup target id: %w", err)
	}

	// 2. Insert scan execution
	rawJSON, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshal scan json: %w", err)
	}

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO scans (id, target_id, started_at, ended_at, pages_seen, risk_score, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?);
	`, scanID, targetID, result.StartedAt, result.EndedAt, result.PagesSeen, result.RiskScore, string(rawJSON))
	if err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}

	// 3. Index evidence items into bipartite relational tables
	if err := s.indexEvidenceTx(tx, targetID, scanID, result); err != nil {
		return "", fmt.Errorf("index evidence: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit scan transaction: %w", err)
	}

	return scanID, nil
}

func (s *SQLiteStore) indexEvidenceTx(tx *sql.Tx, targetID int64, scanID string, result model.ScanResult) error {
	for _, f := range result.Findings {
		for _, ev := range f.Evidence {
			// Safety rule: never index raw credentials
			if ev.Type == model.EvidenceCredential {
				continue
			}

			val := strings.TrimSpace(ev.Description)
			if val == "" {
				continue
			}

			canon := CanonicalizeValue(ev.Type, val)
			hash := ValueHash(ev.Type, canon)

			// Upsert evidence entity
			_, err := tx.Exec(`
				INSERT INTO evidence_items (evidence_type, canonical_value, value_hash, first_seen_at, last_seen_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(evidence_type, value_hash) DO UPDATE SET
					last_seen_at = excluded.last_seen_at;
			`, string(ev.Type), canon, hash, result.StartedAt, result.EndedAt)
			if err != nil {
				return err
			}

			var evidenceID int64
			err = tx.QueryRow(`SELECT id FROM evidence_items WHERE evidence_type = ? AND value_hash = ?`, string(ev.Type), hash).Scan(&evidenceID)
			if err != nil {
				return err
			}

			// Upsert target-evidence link
			_, err = tx.Exec(`
				INSERT INTO target_evidence (target_id, evidence_id, first_seen_at, last_seen_at, last_scan_id, source_url, observation_count)
				VALUES (?, ?, ?, ?, ?, ?, 1)
				ON CONFLICT(target_id, evidence_id) DO UPDATE SET
					last_seen_at = excluded.last_seen_at,
					last_scan_id = excluded.last_scan_id,
					source_url = CASE WHEN excluded.source_url != '' THEN excluded.source_url ELSE target_evidence.source_url END,
					observation_count = target_evidence.observation_count + 1;
			`, targetID, evidenceID, result.StartedAt, result.EndedAt, scanID, ev.Source)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// IndexEvidence indexes evidence items from a scan result.
func (s *SQLiteStore) IndexEvidence(result model.ScanResult) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var targetID int64
	err = tx.QueryRow(`SELECT id FROM targets WHERE onion_address = ?`, result.Target.Onion).Scan(&targetID)
	if err != nil {
		// Target may not be registered yet, create it
		_, err = tx.Exec(`
			INSERT INTO targets (onion_address, first_scanned_at, last_scanned_at, total_scans)
			VALUES (?, ?, ?, 1)
			ON CONFLICT(onion_address) DO NOTHING;
		`, result.Target.Onion, result.StartedAt, result.EndedAt)
		if err != nil {
			return err
		}
		_ = tx.QueryRow(`SELECT id FROM targets WHERE onion_address = ?`, result.Target.Onion).Scan(&targetID)
	}

	scanID := result.EndedAt.UTC().Format("20060102T150405Z")
	if err := s.indexEvidenceTx(tx, targetID, scanID, result); err != nil {
		return err
	}

	return tx.Commit()
}

// History returns all past scans for a target, ordered oldest first.
func (s *SQLiteStore) History(onion string) ([]model.ScanResult, error) {
	rows, err := s.db.Query(`
		SELECT s.raw_json
		FROM scans s
		JOIN targets t ON s.target_id = t.id
		WHERE t.onion_address = ?
		ORDER BY s.ended_at ASC;
	`, onion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.ScanResult
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r model.ScanResult
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

// Latest returns the most recent scan for a target, or ok=false if none exist.
func (s *SQLiteStore) Latest(onion string) (model.ScanResult, bool, error) {
	var raw string
	err := s.db.QueryRow(`
		SELECT s.raw_json
		FROM scans s
		JOIN targets t ON s.target_id = t.id
		WHERE t.onion_address = ?
		ORDER BY s.ended_at DESC
		LIMIT 1;
	`, onion).Scan(&raw)
	if err == sql.ErrNoRows {
		return model.ScanResult{}, false, nil
	}
	if err != nil {
		return model.ScanResult{}, false, err
	}

	var r model.ScanResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return model.ScanResult{}, false, err
	}
	return r, true, nil
}

// GetScan returns a specific past scan by target onion and scan ID.
func (s *SQLiteStore) GetScan(onion string, scanID string) (model.ScanResult, bool, error) {
	scanID = strings.TrimSuffix(scanID, ".json")
	var raw string
	err := s.db.QueryRow(`
		SELECT s.raw_json
		FROM scans s
		JOIN targets t ON s.target_id = t.id
		WHERE t.onion_address = ? AND s.id = ?;
	`, onion, scanID).Scan(&raw)
	if err == sql.ErrNoRows {
		return model.ScanResult{}, false, nil
	}
	if err != nil {
		return model.ScanResult{}, false, err
	}

	var r model.ScanResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return model.ScanResult{}, false, err
	}
	return r, true, nil
}

// Targets returns all onion targets recorded in the store.
func (s *SQLiteStore) Targets() ([]string, error) {
	rows, err := s.db.Query(`SELECT onion_address FROM targets ORDER BY onion_address ASC;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		targets = append(targets, addr)
	}
	return targets, nil
}

// FindCoOccurringTargets returns all targets that have exhibited the specified evidence.
func (s *SQLiteStore) FindCoOccurringTargets(evType model.EvidenceType, rawVal string) ([]TargetLink, error) {
	canon := CanonicalizeValue(evType, rawVal)
	hash := ValueHash(evType, canon)

	rows, err := s.db.Query(`
		SELECT t.onion_address, te.first_seen_at, te.last_seen_at, te.last_scan_id, te.source_url
		FROM target_evidence te
		JOIN targets t ON te.target_id = t.id
		JOIN evidence_items e ON te.evidence_id = e.id
		WHERE e.evidence_type = ? AND e.value_hash = ?
		ORDER BY t.onion_address ASC;
	`, string(evType), hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []TargetLink
	for rows.Next() {
		var link TargetLink
		var sourceURL sql.NullString
		if err := rows.Scan(&link.Onion, &link.FirstSeen, &link.LastSeen, &link.LastScanID, &sourceURL); err != nil {
			return nil, err
		}
		if sourceURL.Valid && sourceURL.String != "" {
			link.Sources = []string{sourceURL.String}
		}
		links = append(links, link)
	}
	return links, nil
}

// ListAssets returns evidence items and their associated targets, optionally filtered by target and evidence type.
func (s *SQLiteStore) ListAssets(target string, evType model.EvidenceType) ([]AssetItem, error) {
	var query strings.Builder
	var args []interface{}

	query.WriteString(`
		SELECT e.evidence_type, e.canonical_value, e.first_seen_at, e.last_seen_at,
		       (SELECT GROUP_CONCAT(t2.onion_address)
		        FROM target_evidence te2
		        JOIN targets t2 ON te2.target_id = t2.id
		        WHERE te2.evidence_id = e.id) AS peers
		FROM evidence_items e
	`)

	var where []string
	if target != "" {
		where = append(where, `e.id IN (SELECT te.evidence_id FROM target_evidence te JOIN targets t ON te.target_id = t.id WHERE t.onion_address = ?)`)
		args = append(args, target)
	}
	if evType != "" {
		where = append(where, `e.evidence_type = ?`)
		args = append(args, string(evType))
	}

	if len(where) > 0 {
		query.WriteString(" WHERE " + strings.Join(where, " AND "))
	}

	query.WriteString(" ORDER BY e.last_seen_at DESC, e.canonical_value ASC;")

	rows, err := s.db.Query(query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AssetItem
	for rows.Next() {
		var item AssetItem
		var evTypeStr string
		var peers sql.NullString
		if err := rows.Scan(&evTypeStr, &item.CanonicalValue, &item.FirstSeen, &item.LastSeen, &peers); err != nil {
			return nil, err
		}
		item.Type = model.EvidenceType(evTypeStr)
		if peers.Valid && peers.String != "" {
			rawPeers := strings.Split(peers.String, ",")
			item.CoOccurringTargets = dedupeStrings(rawPeers)
		}
		items = append(items, item)
	}
	return items, nil
}
