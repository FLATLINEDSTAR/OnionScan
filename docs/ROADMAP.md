# Roadmap

Phases are sequential on purpose — each one is a prerequisite for the next
being worth doing. Don't jump to Phase 5 with a weak Phase 1.

## Phase 1 — MVP (this scaffold)

- [x] Project structure, analyzer plugin interface
- [x] Tor SOCKS5 client (dependency-free)
- [x] Bounded same-origin crawler
- [x] Headers analyzer (server disclosure, missing security headers)
- [x] OPSEC analyzer (email, IP, internal-IP regex evidence)
- [x] Fingerprint analyzer (response signature, MVP only)
- [x] MVP correlation (same-scan IP + fingerprint co-occurrence)
- [x] Risk scoring
- [x] JSON + Markdown report output
- [x] Filesystem-backed scan history
- [ ] Unit tests for every package above (see issues)
- [ ] `onionsec scan` config file support (timeouts, limits, SOCKS address)

## Phase 2 — Security engine

- [ ] TLS analyzer (certificate fields, weak ciphers if HTTPS is used)
- [ ] `robots.txt` / sitemap analyzer
- [ ] Source map / JS bundle analyzer (static only — see safety rules)
- [ ] External-resource analyzer (cross-origin script/img/link tags)
- [ ] API endpoint detection (common REST/GraphQL path patterns)
- [ ] Credential/secret pattern analyzer (API keys, private key headers)
- [ ] EXIF/image metadata analyzer

## Phase 3 — Correlation engine (the differentiator)

- [ ] Persistent evidence store keyed by evidence value, not just scan
- [ ] Cross-target evidence graph (same IP/cert/fingerprint across
      multiple different `.onion` targets scanned by the same user)
- [ ] Confidence model: replace the fixed bump in
      `internal/correlation` with a weighted scoring function
- [ ] `onionsec graph <target>` — render the evidence graph (text/DOT first,
      Cytoscape.js later per the dashboard phase)

## Phase 4 — Monitoring

- [x] Implement `onionsec monitor`: run a scan, diff against `storage.Store.Latest`, print
      NEW / REMOVED / CHANGED sections
- [x] Migrate `internal/storage` from JSON files to SQLite
- [x] Scan comparison command: `onionsec diff <target> <scan-id> <scan-id>`
- [x] Scheduled/recurring scan support (cron-friendly CLI flags first,
      daemon mode later)

## Phase 5 — API + dashboard (only after 1–4 are solid)

- [x] `POST /v1/scans`, `GET /v1/scans/:id`, `GET /v1/findings`,
      `GET /v1/assets`, `GET /v1/history`
- [x] React/Next.js dashboard consuming the API
- [ ] Evidence graph visualization (Cytoscape.js)

## Explicit non-goals

- No dark-web crawling / onion address discovery.
- No "AI-powered" marketing or ungrounded ML claims.
- No deanonymization claims — findings are framed as "potential disclosure,"
  never "we found the real IP."
- No SaaS dashboard before the CLI + correlation engine are trustworthy.
