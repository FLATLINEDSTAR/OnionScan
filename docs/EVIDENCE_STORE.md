# Persistent Evidence Store Schema

## 1. Overview & Problem Statement

In OnionSec, an observation made by an analyzer is **evidence**, not an accusation. A single scan of an onion target records evidence such as:
- Clearnet IP references (`model.EvidenceIP`)
- TLS certificate fingerprints and subject names (`model.EvidenceTLS`)
- HTTP response header signatures (`model.EvidenceFingerprint`)
- Third-party tracking and analytics identifiers (`model.EvidenceExternalRes`)
- Operator contact emails (`model.EvidenceEmail`)

### The Cross-Target Opportunity
While same-scan correlation (e.g. `INFRA-002`) correlates co-occurring evidence within a single scan of a single target, the true differentiator of OnionSec (Phase 3 of `docs/ROADMAP.md`) is **cross-target correlation**:
- Detecting when two or more distinct `.onion` addresses reference the **same origin IP address**.
- Detecting when different onion services present the **same TLS certificate** or subject alternative names (SANs).
- Detecting shared **analytics IDs**, **favicons / header hashes**, or **developer email addresses** across services.

Without an indexed evidence store, identifying shared infrastructure across $N$ targets requires scanning every historical JSON file ($O(N \cdot M)$ disk I/O), which does not scale.

The **Persistent Evidence Store** solves this by maintaining an inverted index keyed by normalized evidence value, enabling $O(1)$ cross-target lookups during scans and instant evidence graph generation.

---

## 2. Graph Data Model (Bipartite Graph)

The evidence relationship space is modeled as an undirected bipartite graph $G = (T, E, L)$:
- **Target Nodes ($T$):** Distinct onion services (e.g. `expyuz5wqqwgah5d...onion`).
- **Evidence Nodes ($E$):** Canonicalized evidence facts (e.g. `ip:198.51.100.42`, `tls_fingerprint:sha256:7b...`).
- **Observation Links ($L$):** Edges connecting a target to an evidence node, annotated with observation provenance (timestamps, scan ID, occurrence count, source URL).

```
[Target A: app1.onion] ──── (seen on /page1) ────▶ [Evidence: ip:198.51.100.42]
                                                          │
                                                    (seen on /api)
                                                          │
[Target B: app2.onion] ───────────────────────────────────┘
```

When Target B is scanned, the correlation engine checks the evidence store for `ip:198.51.100.42` and immediately discovers the relationship to Target A, raising confidence of shared infrastructure.

---

## 3. Canonicalization and Normalization

To ensure that identical real-world entities produce identical index keys regardless of casing, formatting, or protocol variations, all evidence values must be canonicalized prior to indexing:

| Evidence Type | Raw Example | Canonical Form | Normalization Rules |
|---|---|---|---|
| `ip` | `198.51.100.042:8080`, `2001:0DB8::1` | `198.51.100.42`, `2001:db8::1` | Strip port numbers, parse as `net.IP`, format via standard Go IP stringification (lowercase IPv6, zero-stripped IPv4). |
| `hostname` | `Example.COM.` | `example.com` | Lowercase, trim leading/trailing whitespace, trim trailing dot. |
| `tls` | `SHA256:7B:A2:3C:...` | `sha256:7ba23c...` | Strip colons/spaces, lowercase hex representation, preserve hash algorithm prefix. |
| `fingerprint` | `Server: Apache\r\nX-Powered-By: PHP` | `sha256:e3b0c44...` | Cryptographic SHA-256 hash of normalized response header signature. |
| `email` | `Admin@Example.COM` | `admin@example.com` | Lowercase string, strip `mailto:` prefix. |
| `external_resource`| `https://www.google-analytics.com/analytics.js?id=UA-12345-1` | `ua-12345-1` (or domain) | Extract tracked entity ID where applicable; otherwise normalized origin domain. |
| `credential` | `AKIA... (redacted)` | `redacted_hash:<sha256>` | **Safety Rule:** Never index raw secret material. Only index the hash of the redacted descriptor or classification. |

---

## 4. Storage Architectures

To preserve the **dependency-free standard library** architecture of Phase 1–3 while preparing for the **SQLite migration** in Phase 4, the persistent evidence store is designed with two compatible representations:

### 4.1. MVP File-Based Inverted Index (Phase 3)

Stored alongside the scan history in the filesystem (`Store.BaseDir`):

```
<storage_base_dir>/
├── <target_onion_dir>/
│   ├── 20260912T091500Z.json        # Raw ScanResult
│   └── 20260912T102000Z.json
└── .evidence_index/
    ├── ip/
    │   ├── <value_hash>.json        # Index entry for a specific IP
    ├── tls/
    │   ├── <value_hash>.json        # Index entry for a specific TLS cert
    ├── fingerprint/
    │   ├── <value_hash>.json        # Index entry for a response signature
    ├── email/
    │   ├── <value_hash>.json
    └── external_resource/
        └── <value_hash>.json
```

#### Index Entry File Format (`<value_hash>.json`)

The filename is the SHA-256 hash of the canonicalized evidence value string.

```json
{
  "type": "ip",
  "canonical_value": "198.51.100.42",
  "value_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "first_seen": "2026-09-12T08:00:00Z",
  "last_seen": "2026-09-12T09:15:00Z",
  "total_occurrences": 3,
  "targets": [
    {
      "onion": "expyuz5wqqwgah5d.onion",
      "first_seen": "2026-09-12T08:00:00Z",
      "last_seen": "2026-09-12T09:15:00Z",
      "last_scan_id": "20260912T091500Z",
      "sources": ["http://expyuz5wqqwgah5d.onion/contact"]
    },
    {
      "onion": "2f7kbxptkgn5sod2.onion",
      "first_seen": "2026-09-12T08:45:00Z",
      "last_seen": "2026-09-12T08:45:00Z",
      "last_scan_id": "20260912T084500Z",
      "sources": ["http://2f7kbxptkgn5sod2.onion/api"]
    }
  ]
}
```

### 4.2. Phase 4 Relational SQLite Schema

When migrating storage to SQLite in Phase 4 (`docs/ROADMAP.md`), the schema maps directly to relational tables with B-Tree indices:

```sql
-- Target registry
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    onion_address TEXT UNIQUE NOT NULL,
    first_scanned_at TIMESTAMP NOT NULL,
    last_scanned_at TIMESTAMP NOT NULL,
    total_scans INTEGER DEFAULT 1
);

-- Scan executions
CREATE TABLE scans (
    id TEXT PRIMARY KEY, -- e.g. 20260912T091500Z
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    started_at TIMESTAMP NOT NULL,
    ended_at TIMESTAMP NOT NULL,
    pages_seen INTEGER NOT NULL,
    risk_score INTEGER NOT NULL
);

-- Unique evidence entities (deduplicated across entire universe)
CREATE TABLE evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_type TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    first_seen_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    UNIQUE(evidence_type, value_hash)
);

CREATE INDEX idx_evidence_lookup ON evidence_items(evidence_type, canonical_value);

-- Bipartite relationship edges: Target <-> Evidence associations
CREATE TABLE target_evidence (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES evidence_items(id) ON DELETE CASCADE,
    first_seen_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    last_scan_id TEXT NOT NULL REFERENCES scans(id),
    source_url TEXT,
    observation_count INTEGER DEFAULT 1,
    PRIMARY KEY(target_id, evidence_id)
);

CREATE INDEX idx_target_evidence_evidence ON target_evidence(evidence_id);
CREATE INDEX idx_target_evidence_target ON target_evidence(target_id);
```

---

## 5. Core Query Patterns & Index Operations

### 5.1. Operations on Ingestion (Post-Scan Hook)

When `onionsec scan` finishes scanning a target:
1. `RecordScan(result model.ScanResult)` persists the scan JSON.
2. `IndexEvidence(result model.ScanResult)` iterates over each `model.Evidence` in the findings:
   - Canonicalize the value and calculate `value_hash`.
   - Read-modify-write or insert the corresponding index file (`.evidence_index/<type>/<value_hash>.json`).
   - Append or update the current target's record with timestamps and source URLs.

### 5.2. Query: Find Co-Occurring Targets

Given an evidence item observed during a scan, find all other targets that have ever exhibited this exact evidence:

```go
type TargetLink struct {
    TargetOnion string    `json:"target_onion"`
    FirstSeen   time.Time `json:"first_seen"`
    LastSeen    time.Time `json:"last_seen"`
    SourceURL   string    `json:"source_url"`
}

func (idx *EvidenceIndex) FindCoOccurringTargets(evType model.EvidenceType, canonicalVal string) ([]TargetLink, error)
```

**Complexity:** $O(1)$ disk seek by reading `.evidence_index/<type>/<hash>.json`.

### 5.3. Query: Target Evidence Graph (for `onionsec graph`)

Retrieve all evidence nodes linked to a target, and all 1-hop neighbor targets linked via that evidence:

```go
type EvidenceNode struct {
    Type           model.EvidenceType `json:"type"`
    CanonicalValue string             `json:"canonical_value"`
    LinkedTargets  []string           `json:"linked_targets"`
}

func (idx *EvidenceIndex) GetTargetGraph(targetOnion string) ([]EvidenceNode, error)
```

---

## 6. Integration with Correlation Engine & CLI

### 6.1. Cross-Target Correlation (Issue #17)

When `internal/correlation.Correlate` runs:
1. It queries `EvidenceIndex.FindCoOccurringTargets(...)` for high-signal evidence types:
   - Public IP addresses (`model.EvidenceIP`)
   - TLS certificates / SANs (`model.EvidenceTLS`)
   - Tracking scripts / Analytics IDs (`model.EvidenceExternalRes`)
2. If another target shares this evidence:
   - Emit an `INFRA-xxx` or `OPSEC-xxx` finding indicating multi-target correlation.
   - Example finding title: *"Shared infrastructure with 2 other onion services"*.
   - Include the peer onion addresses in the finding evidence.

### 6.2. Weighted Confidence Scoring (Issue #18)

Independence weights scale according to evidence uniqueness:
- A shared unique TLS certificate or custom tracking ID has high uniqueness weight ($w \approx 0.9$).
- A shared common response fingerprint or Cloudflare IP has lower uniqueness weight ($w \approx 0.3$).
- The weighted correlation engine computes:
  $$C = 1 - \prod_{i} (1 - w_i)$$
  preventing false confidence leaps while rewarding corroboration across independent channels.

### 6.3. Graph Command Output (Issue #19)

`onionsec graph <target>` consumes the index to output:
- Text/ASCII tree format:
  ```
  target: expyuz5wqqwgah5d.onion
  ├── ip: 198.51.100.42 (also seen on 2f7kbxptkgn5sod2.onion)
  ├── tls: CN=origin.example.com (unique to target)
  └── analytics: UA-12345678-1 (also seen on 2f7kbxptkgn5sod2.onion)
  ```
- Graphviz DOT format:
  ```dot
  graph G {
    "expyuz5wqqwgah5d.onion" [shape=box];
    "2f7kbxptkgn5sod2.onion" [shape=box];
    "ip:198.51.100.42" [shape=ellipse];
    "expyuz5wqqwgah5d.onion" -- "ip:198.51.100.42";
    "2f7kbxptkgn5sod2.onion" -- "ip:198.51.100.42";
  }
  ```

---

## 7. Operational & Safety Rules

1. **Strict Secret Redaction:** Under no circumstances should unredacted credentials, API keys, or private key material be indexed in the evidence store. Only sanitized strings or cryptographic hashes of redacted labels are permitted.
2. **File Atomicity:** In the file-based MVP index, index writes must use atomic write-and-rename (`tmpfile.tmp` $\to$ `<hash>.json`) to prevent corruption during unexpected shutdowns.
3. **No Dark-Web Enumeration:** The evidence store only contains records from targets explicitly scanned by the user. No automatic outbound crawler discovery or crawling is performed.
