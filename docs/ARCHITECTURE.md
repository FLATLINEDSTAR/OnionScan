# Architecture

## Design goals

1. **Evidence, not accusations.** A single IP address, email, or header
   value is *evidence*. A Finding with high severity/confidence should
   only be emitted when multiple independent pieces of evidence agree, or
   when the observation is unambiguous by itself (e.g. a missing security
   header is just a fact, not a leap).
2. **Modular analyzers.** Every detector implements
   `internal/analyzer.Analyzer`. New checks are additive — they don't
   require touching the crawler, correlation engine, or CLI.
3. **CLI first.** No dashboard, no SaaS, no persistent server until
   scan → analyze → correlate → monitor is solid on the command line. See
   `docs/ROADMAP.md`.
4. **Dependency-light.** The MVP intentionally uses only the Go standard
   library (including a small hand-rolled SOCKS5 client in
   `internal/tor`) so the project builds anywhere with just a Go toolchain
   and a running Tor daemon — no module proxy, no cgo, no SQLite driver.
   This is a deliberate MVP tradeoff, not a permanent constraint: Phase 4
   revisits storage (SQLite) once monitoring needs real queries.

## Data flow

```
Target (.onion)
   │
   ▼
Crawler ──same-origin, bounded pages/bytes/time──▶ []Page
   │
   ▼
Analyzers (headers, opsec, fingerprint, ...) ──▶ []Finding (with Evidence)
   │
   ▼
Correlation engine ──▶ additional higher-confidence []Finding
   │
   ▼
Risk engine ──▶ 0-100 score
   │
   ▼
Report (Markdown/JSON) + Storage (scan history)
```

## Why evidence-first, not "IP detection"

Finding a bare IPv4 address in a page does not mean it's the origin
server — it could be a CDN, an unrelated third-party API, a documentation
example, or an old address. `internal/analyzer/opsec` therefore emits
*low*-confidence evidence for a standalone IP mention (`INFRA-001`,
confidence 0.4) and leaves it to `internal/correlation` to raise
confidence when independent evidence (e.g. a matching response
fingerprint) corroborates it (`INFRA-002`).

This is the project's actual differentiator versus a "grep for IPs"
scanner, and it's why `internal/correlation` is called out as its own
package rather than folded into the analyzers.

## Safety rules (non-negotiable)

A security scanner that fetches attacker-controlled content is itself an
attack surface. OnionSec must:

- **Never execute target JavaScript** on the scanner host. Static analysis
  only (see the planned JS/source-map analyzer in the roadmap).
- **Bound every crawl**: max pages, max body size per page, per-page
  timeout, total wall-clock budget (`internal/crawler.Limits`).
- **Same-origin crawl only.** Cross-origin links are recorded as external
  resources, never followed.
- **Redact secrets from reports.** If a future credential-detection
  analyzer finds a live-looking secret, the report should show enough to
  identify the finding (e.g. a hash or truncated value) without
  reproducing the full secret in a file that might be shared or committed.
- **No dark-web crawling.** OnionSec only scans targets explicitly
  supplied by the user. It does not discover or enumerate onion addresses
  on its own. See `README.md` for the authorized-use requirement.

## Naming note

The repository is named `OnionScan` (matching the original project this
grew out of), but the binary and internal Go module path use `onionsec` /
`OnionScan` respectively to avoid confusion with the unrelated, actively
maintained OnionScan project.

If you rename the GitHub repository later (e.g. to `github.com/<org>/OnionSec`),
run the provided automation script to update `go.mod` and all internal import
declarations:

```bash
./scripts/rename_module.sh github.com/<new-org>/<new-repo>
```

This updates `go.mod`, rewires all internal package imports across the codebase,
formats source files with `gofmt`, and verifies compilation and tests with
`go vet` and `go test ./...`.

