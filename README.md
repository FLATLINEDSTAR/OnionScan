# OnionSec

**Security observability for Tor onion services.**

Scan → Analyze → Correlate → Monitor

OnionSec helps operators of `.onion` services find accidental
infrastructure, metadata, and configuration exposure before someone else
does — and gives researchers an evidence-based way to correlate findings
instead of trusting a single regex match.

> ⚠️ **Authorized use only.** Only run OnionSec against onion services you
> own or have explicit permission to test. This tool detects *potential
> information and infrastructure disclosures* — it does not, and is not
> intended to, deanonymize services you don't control.

## Why not just use OnionScan?

The original [OnionScan](https://github.com/s-rah/onionscan) and its
actively-maintained modern rewrite already do single-shot scanning well.
OnionSec's bet is different: raw regex hits (an IP, an email, a header) are
**evidence**, not proof. The value is in turning evidence into
correlated, confidence-scored findings, and in tracking how a service's
exposure changes over time. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the full reasoning.

## Status

Early scaffold (Phase 1 / MVP). See [`docs/ROADMAP.md`](docs/ROADMAP.md) and
the [issue tracker](../../issues) for what's built vs. planned.

## Quick start

### Prerequisites & Build Requirements

- **Go**: 1.22+
- **C Compiler (CGO)**: SQLite persistence uses `github.com/mattn/go-sqlite3`, requiring `CGO_ENABLED=1` and a standard C compiler (`gcc` or `clang`, installed via `build-essential` on Debian/Ubuntu or `xcode-select` on macOS).
- **Tor Daemon**: A running Tor daemon (default SOCKS5 port `127.0.0.1:9050`).

```bash
go build -o onionsec ./cmd/onionsec

# scan a target you own/are authorized to test
./onionsec scan youronionaddresshere.onion

# re-render the last saved report
./onionsec report youronionaddresshere.onion

# monitor changes against past scans
./onionsec monitor youronionaddresshere.onion

# compare two specific past scans
./onionsec diff youronionaddresshere.onion <scan-id-1> <scan-id-2>

# generate evidence correlation graph (ASCII or DOT)
./onionsec graph youronionaddresshere.onion
```

Scan history and relational evidence indexing are persisted in a local SQLite database at `~/.onionsec/onionsec.db`.

## How it works

```
CLI
 │
Scan Engine  →  Tor SOCKS client  →  Crawler (same-origin, bounded)
 │
Analyzers (headers, opsec regex, fingerprint, ...)  → Evidence
 │
Correlation Engine  → higher-confidence Findings
 │
Risk Engine  → 0-100 score
 │
Report (Markdown / JSON)  +  Storage (scan history)
```

Every analyzer implements one small interface
(`internal/analyzer.Analyzer`) so new detectors are easy to contribute —
see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Project layout

```
cmd/onionsec/          CLI entry point
internal/model/        Target, Page, Finding, Evidence, ScanResult types
internal/analyzer/     Analyzer interface + built-in analyzers (headers, opsec, fingerprint)
internal/tor/          Dependency-free SOCKS5 client + Tor-routed HTTP client
internal/crawler/      Bounded same-origin crawler
internal/correlation/  Evidence → higher-confidence findings
internal/risk/         Finding list → 0-100 risk score
internal/report/       JSON / Markdown renderers
internal/storage/      Scan history persistence
internal/scan/         Orchestrates the above into one `Run()`
docs/                  Architecture, roadmap, rule catalog
```

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md). Short version:

1. **MVP** — crawl, basic analyzers, JSON/Markdown reports *(this scaffold)*
2. **Security engine** — TLS, JS/source-map analysis, secret detection, more analyzers
3. **Correlation engine** — the real evidence graph (this is the differentiator)
4. **Monitoring** — `onionsec monitor` diffing scans over time, SQLite storage
5. **API + dashboard** — only after 1–4 are solid

## Contributing

Issues are organized by phase and labeled so you can pick up small, mergeable
pieces of work. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to add a
new analyzer or rule, and the [open issues](../../issues) to find one to
work on.

## License

MIT — see [`LICENSE`](LICENSE).
