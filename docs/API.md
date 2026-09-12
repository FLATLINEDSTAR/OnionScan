# OnionSec HTTP API Specification

**Version:** `v1`  
**Base Path:** `/v1`  
**Media Type:** `application/json`

This document defines the HTTP API server specification for OnionSec (`cmd/onionsecd/`), providing programmatic access to scanning, monitoring, evidence indexing, cross-target correlation, and graph visualization.

---

## 1. Architecture & Design Principles

The API server (`cmd/onionsecd/`) is a lightweight HTTP service designed to run alongside or in containerized environments with Tor:

```
┌───────────────────────────────────────────────────────────────┐
│                     Clients & Dashboard                       │
│              (React/Next.js UI, curl, CI/CD)                  │
└───────────────────────────────┬───────────────────────────────┘
                                │ HTTP / JSON
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                 OnionSec Daemon (onionsecd)                   │
│  - Bearer Token Auth Middleware                               │
│  - Request Validation & Rate Limiting                         │
│  - CORS & Security Headers                                    │
└───────────────┬───────────────────────────────┬───────────────┘
                │                               │
                ▼                               ▼
  ┌───────────────────────────┐   ┌───────────────────────────┐
  │     internal/scan         │   │     internal/storage      │
  │  (Crawl, Analyzers, Risk) │   │  (SQLite relational DB)   │
  └─────────────┬─────────────┘   └─────────────┬─────────────┘
                │                               │
                ▼                               ▼
  ┌───────────────────────────┐   ┌───────────────────────────┐
  │     Tor SOCKS5 Daemon     │   │      ~/.onionsec/db       │
  │     (127.0.0.1:9050)      │   │  (Bipartite Evidence)     │
  └───────────────────────────┘   └───────────────────────────┘
```

### Core Tenets
1. **Direct Package Reuse**: Reuses `internal/scan.Run`, `internal/storage.Store`, `internal/diff`, and `internal/graph` directly without code duplication.
2. **Authorized-Use Invariants**: Scans are bounded by same-origin crawler limits and request timeouts. Credentials are never returned unredacted or stored as indexed assets.
3. **Stateless Operations with Persistent Storage**: The server persists all runs and evidence in SQLite, allowing horizontal restarts without state loss.

---

## 2. Authentication & Security

All API endpoints (except `/healthz`) require authentication.

### Authentication Methods
Clients authenticate using an HTTP Bearer Token or API key header:
```http
Authorization: Bearer <ONIONSEC_API_KEY>
```
or
```http
X-API-Key: <ONIONSEC_API_KEY>
```

### Configuration
The expected token is loaded via:
1. Environment variable: `ONIONSEC_API_KEY`
2. Config file: `api.auth_token` in `onionsec.yaml`

If no key is configured in development, a warning is logged and a default development token is enabled. In production environments, missing keys will prevent server startup.

### Unauthorized Response (`401 Unauthorized`)
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or missing authorization credentials"
  }
}
```

---

## 3. Standard Response Format

All error responses return a standardized JSON structure:

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "No scan matching ID '20260912T100000Z' was found for target 'service.onion'",
    "details": null
  }
}
```

Standard HTTP status codes:
- `200 OK`: Request succeeded.
- `201 Created`: Resource successfully initiated.
- `202 Accepted`: Asynchronous scan accepted for processing.
- `400 Bad Request`: Malformed JSON or invalid parameter syntax.
- `401 Unauthorized`: Missing or invalid Bearer token.
- `404 Not Found`: Target, scan ID, or asset not found.
- `422 Unprocessable Entity`: Validation failure (e.g. invalid onion address format).
- `500 Internal Server Error`: Server failure or database error.
- `503 Service Unavailable`: Tor SOCKS proxy unreachable.

---

## 4. Endpoints

### 4.1 System Health
#### `GET /healthz`
Public liveness and readiness probe.

**Response (`200 OK`):**
```json
{
  "status": "healthy",
  "version": "0.1.0-dev",
  "storage": "connected",
  "tor_proxy": "reachable"
}
```

---

### 4.2 Target Management
#### `GET /v1/targets`
Retrieves a list of all targets currently tracked in the database.

**Response (`200 OK`):**
```json
{
  "targets": [
    {
      "onion": "expyuzvj2wvx2n7wzrq4yquz7x7lcv7f4z2f4r6r6b7w6y6x7z2f4r6d.onion",
      "first_scanned_at": "2026-09-10T12:00:00Z",
      "last_scanned_at": "2026-09-12T14:30:00Z",
      "total_scans": 5,
      "latest_risk_score": 42
    }
  ]
}
```

---

### 4.3 Scans
#### `POST /v1/scans`
Initiates a scan against a specified onion target.

**Request Headers:**
```http
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "target": "example23456789.onion",
  "async": false,
  "limits": {
    "max_pages": 30,
    "max_depth": 3,
    "max_body_byte": 1048576,
    "page_timeout": "10s",
    "total_budget": "3m"
  }
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | string | Yes | - | Valid Tor `.onion` address |
| `async` | boolean | No | `false` | When true, returns immediately with a task ID |
| `limits.max_pages` | integer | No | `50` | Maximum crawl page limit |
| `limits.max_depth` | integer | No | `3` | Maximum link traversal depth |
| `limits.max_body_byte` | integer | No | `1048576` | Max response body limit in bytes |
| `limits.page_timeout` | string | No | `"10s"` | Per-page HTTP fetch timeout |
| `limits.total_budget` | string | No | `"5m"` | Total budget duration for scan |

**Synchronous Response (`201 Created`):**
```json
{
  "id": "20260912T120000Z",
  "target": "example23456789.onion",
  "status": "completed",
  "started_at": "2026-09-12T11:59:15Z",
  "ended_at": "2026-09-12T12:00:00Z",
  "pages_seen": 14,
  "risk_score": 45,
  "findings_count": 4,
  "findings": [
    {
      "id": "SEC-001",
      "title": "Clearnet hostname in TLS certificate",
      "severity": "HIGH",
      "confidence": 0.95,
      "analyzer": "tls",
      "evidence": [
        {
          "type": "tls",
          "description": "api.clearnet-service.com",
          "source": "https://example23456789.onion:443"
        }
      ],
      "explanation": "Clearnet hostnames in certificates deanonymize service infrastructure.",
      "recommendation": "Use onion-only certificates or disable HTTPS over Tor."
    }
  ]
}
```

**Asynchronous Response (`202 Accepted`):**
```json
{
  "id": "20260912T120000Z",
  "target": "example23456789.onion",
  "status": "queued",
  "started_at": "2026-09-12T12:00:00Z",
  "status_url": "/v1/scans/20260912T120000Z?target=example23456789.onion"
}
```

---

#### `GET /v1/scans/:id`
Retrieves a single historical scan by its scan ID.

**Query Parameters:**
- `target` (required): The target onion address corresponding to the scan.

**Response (`200 OK`):**
Returns the full `ScanResult` JSON representation (identical to the output of `internal/storage.Store.GetScan`).

---

### 4.4 Findings
#### `GET /v1/findings`
Lists findings across scans, with flexible filtering.

**Query Parameters:**
- `target` (optional): Filter findings for a specific onion service.
- `severity` (optional): Filter by minimum severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `analyzer` (optional): Filter by analyzer (`headers`, `opsec`, `tls`, `robots`, `jsanalysis`, `external`, `apidetect`, `credentials`, `metadata`).

**Response (`200 OK`):**
```json
{
  "target": "example23456789.onion",
  "total": 2,
  "findings": [
    {
      "id": "OPSEC-001",
      "title": "Clearnet resource dependency",
      "severity": "MEDIUM",
      "confidence": 0.85,
      "target": "example23456789.onion",
      "analyzer": "external",
      "evidence": [
        {
          "type": "external_resource",
          "description": "https://code.jquery.com/jquery-3.6.0.min.js",
          "source": "http://example23456789.onion/index.html"
        }
      ],
      "created_at": "2026-09-12T12:00:00Z"
    }
  ]
}
```

---

### 4.5 Assets & Evidence Index
#### `GET /v1/assets`
Exposes the inverted evidence index from SQLite (`evidence_items` and `target_evidence`).

**Query Parameters:**
- `target` (optional): Filter assets observed on a specific target.
- `type` (optional): Filter by evidence type (`ip`, `hostname`, `tls`, `http_header`, `fingerprint`, `metadata`, `email`, `external_resource`).

**Response (`200 OK`):**
```json
{
  "total": 3,
  "assets": [
    {
      "type": "ip",
      "canonical_value": "198.51.100.42",
      "first_seen": "2026-09-10T10:00:00Z",
      "last_seen": "2026-09-12T12:00:00Z",
      "co_occurring_targets": [
        "service-alpha.onion",
        "service-beta.onion"
      ]
    },
    {
      "type": "email",
      "canonical_value": "security@operator.org",
      "first_seen": "2026-09-12T12:00:00Z",
      "last_seen": "2026-09-12T12:00:00Z",
      "co_occurring_targets": [
        "service-alpha.onion"
      ]
    }
  ]
}
```

---

### 4.6 Scan History
#### `GET /v1/history`
Returns chronological scan runs and risk score progression for a target.

**Query Parameters:**
- `target` (required): Target onion address.
- `limit` (optional): Maximum number of historical records to return (default: `50`).

**Response (`200 OK`):**
```json
{
  "target": "example23456789.onion",
  "history": [
    {
      "scan_id": "20260910T120000Z",
      "ended_at": "2026-09-10T12:00:00Z",
      "pages_seen": 10,
      "risk_score": 60,
      "findings_count": 4
    },
    {
      "scan_id": "20260912T120000Z",
      "ended_at": "2026-09-12T12:00:00Z",
      "pages_seen": 14,
      "risk_score": 45,
      "findings_count": 3
    }
  ]
}
```

---

### 4.7 Evidence Graph & Diffing (Phase 5 Dashboard Extensions)

#### `GET /v1/graph`
Returns graph visualization topology formatted for Cytoscape.js and graph renderers.

**Query Parameters:**
- `target` (required): Target onion address.

**Response (`200 OK`):**
```json
{
  "target": "service-alpha.onion",
  "elements": {
    "nodes": [
      { "data": { "id": "target", "label": "service-alpha.onion", "type": "target" } },
      { "data": { "id": "ev_ip_198.51.100.42", "label": "198.51.100.42", "type": "ip" } },
      { "data": { "id": "peer_service-beta.onion", "label": "service-beta.onion", "type": "peer" } }
    ],
    "edges": [
      { "data": { "source": "target", "target": "ev_ip_198.51.100.42", "label": "exhibits" } },
      { "data": { "source": "ev_ip_198.51.100.42", "target": "peer_service-beta.onion", "label": "co-occurs" } }
    ]
  }
}
```

#### `GET /v1/diff`
Returns finding differentials between two specific scans.

**Query Parameters:**
- `target` (required): Target onion address.
- `old_scan` (required): Baseline scan ID.
- `new_scan` (required): Comparison scan ID.

**Response (`200 OK`):**
Returns the structured `diff.DiffResult` object containing `new_findings`, `removed_findings`, `changed_findings`, `score_delta`, and `unchanged_count`.

---

## 5. Implementation Guide (`cmd/onionsecd`)

The HTTP server will be implemented in `cmd/onionsecd/main.go` and `internal/api/` using standard Go stdlib (`net/http` and `http.ServeMux`):
- Routing handles `/v1/*` patterns with sub-routers.
- Handlers access `storage.Store` for persistence queries and `scan.Run` for scan executions.
- Graceful server shutdown on `SIGINT`/`SIGTERM` via `http.Server.Shutdown`.
- Automated testing via `net/http/httptest`.
