# OnionSec Monitoring & Scheduled Operations

This guide covers OnionSec's monitoring engine, SQLite storage architecture, scan diffing mechanics, and cron/systemd scheduling.

---

## 1. Overview

Single-shot scans produce a point-in-time snapshot of an onion service. However, operational security risks often emerge gradually:
- A developer enables debug endpoints or deploys source maps.
- A new third-party tracking script or asset is unintentionally introduced.
- An infrastructure leak discloses a public/private IP address or clearnet hostname in a certificate.
- A secret token or API key is committed to client-side bundles.

OnionSec's **Monitoring System** tracks services over time by executing new scans, comparing them against the target's baseline history, and reporting only actionable changes.

```
                  ┌───────────────────────────────┐
                  │    Target Onion Service(s)    │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │    Crawler & Analyzers      │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │     Correlation & Risk      │
                   └──────────────┬──────────────┘
                                  │
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼
 ┌───────────────────────────┐         ┌───────────────────────────┐
 │   SQLite Evidence Store   │ ◄───────┤       Diff Engine         │
 │     (~/.onionsec/db)      │         │   (NEW / REMOVED / CHG)   │
 └───────────────────────────┘         └─────────────┬─────────────┘
                                                     │
                                                     ▼
                                       ┌───────────────────────────┐
                                       │ Human / JSON / MD Reports │
                                       │   (Cron & Alert Ready)    │
                                       └───────────────────────────┘
```

---

## 2. Storage Architecture (SQLite)

OnionSec uses a relational SQLite database (stored by default at `~/.onionsec/onionsec.db` or configured via `ONIONSEC_DATA_DIR`).

### Relational Schema

1. **`targets`**:
   - Stores registered onion addresses, timestamps of first and last scans, and total scan counts.
2. **`scans`**:
   - Stores each scan run identified by timestamp (`YYYYMMDDTHHMMSSZ`) scoped per target (`PRIMARY KEY (target_id, id)`).
   - Stores pages crawled, risk score (0–100), and the complete `raw_json` representation.
3. **`evidence_items`**:
   - Canonicalized, hashed evidence entities (`canonical_value`, `value_hash`, `evidence_type`).
   - Safety rule: Raw credentials (`CRED-001`/`CRED-002`) are **never** indexed into evidence entities.
4. **`target_evidence`**:
   - Bipartite join table linking targets with observed evidence.
   - Maintains `observation_count`, `first_seen_at`, `last_seen_at`, `last_scan_id`, and `source_url`.

### Concurrency & Performance
- Uses SQLite Write-Ahead Logging (`WAL` mode) for concurrent reads and non-blocking writes.
- B-Tree indexes on `(target_id, ended_at)`, `(evidence_type, value_hash)`, and join foreign keys.

---

## 3. Finding Lifecycle & Diffing Engine

When `onionsec monitor` runs, it compares the newly completed scan with the most recent prior scan (`storage.Store.Latest`):

- **`[+] NEW FINDINGS`**: Findings present in the current scan that did not exist in the baseline scan.
- **`[-] REMOVED / RESOLVED FINDINGS`**: Findings present in the baseline scan that are no longer detected (e.g., exposed email was removed or debug endpoint disabled).
- **`[~] CHANGED FINDINGS`**: Findings whose severity changed, whose confidence shifted by $\ge 0.05$, or where additional corroborating evidence was observed.
- **Risk Score Delta**: Displays changes in the overall risk score (e.g. `+15` or `-10`).

---

## 4. CLI Usage

### Basic Monitoring
Scan target and compare against previous scan:
```bash
onionsec monitor yourservice.onion
```

Export diff reports in JSON or Markdown format:
```bash
onionsec monitor yourservice.onion --json report.json --md report.md
```

### Standalone Historical Diffing
Compare any two past scans by their scan IDs:
```bash
onionsec diff yourservice.onion 20260910T120000Z 20260912T120000Z
```

---

## 5. Scheduled & Recurring Execution

### Cron-Friendly CLI Flags

OnionSec provides dedicated flags designed for cron jobs and automation pipelines:

| Flag | Description |
|---|---|
| `--quiet`, `-q` | Suppresses standard output when no changes or threshold breaches occur. Output is only produced when differences or alerts exist. |
| `--fail-on-changes` | Exits with status code `2` if any findings were added, removed, or modified. Exits with `0` on clean runs. |
| `--fail-above-score <N>` | Exits with status code `2` if the target's risk score exceeds threshold `N`. |
| `--targets-file <path>` | Reads a list of target onions (one per line, ignoring `#` comments and blank lines) and monitors each in sequence. |
| `--interval <duration>` | Runs as a recurring loop within the process (e.g. `1h`, `24h`), handling `SIGINT`/`SIGTERM` gracefully. |

### Exit Codes
- `0`: Success, no changes detected, score within threshold.
- `1`: Execution failure (CLI usage error, network error, invalid config).
- `2`: Security event triggered (changes detected with `--fail-on-changes` or score exceeded threshold with `--fail-above-score`).

---

## 6. Scheduling Recipes

### A. Crontab (Hourly Alerting on Changes)

Add to `crontab -e`:

```cron
# Monitor onion service every hour.
# If changes are found, output is printed and cron sends an alert email to the operator.
# If nothing changes, --quiet keeps stdout silent so no empty emails are sent.
0 * * * * /usr/local/bin/onionsec monitor myfleet.onion --quiet --fail-on-changes
```

### B. Fleet Monitoring from Targets File

Create `/etc/onionsec/targets.txt`:
```text
# OnionSec fleet monitoring targets
http://marketplace37xq2...onion
http://forum92kxp5q...onion
http://api884zpl01...onion
```

Schedule daily scan:
```cron
# Scan all targets every day at 02:00 UTC
0 2 * * * /usr/local/bin/onionsec monitor --targets-file /etc/onionsec/targets.txt --quiet --fail-above-score 50
```

### C. Systemd Service & Timer

Create `/etc/systemd/system/onionsec-monitor.service`:
```ini
[Unit]
Description=OnionSec Target Monitoring
After=network.target tor.service
Wants=tor.service

[Service]
Type=oneshot
User=onionsec
ExecStart=/usr/local/bin/onionsec monitor --targets-file /etc/onionsec/targets.txt --quiet --fail-on-changes
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/onionsec-monitor.timer`:
```ini
[Unit]
Description=Run OnionSec Monitor Daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start the timer:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now onionsec-monitor.timer
```

### D. In-Process Loop Mode (Docker / Container)

Run OnionSec continuously inside a container with `--interval`:
```bash
./onionsec monitor --targets-file /data/targets.txt --interval 12h --quiet --fail-on-changes
```
