# Rule catalog

Every Finding has a stable `ID` so users can suppress/allowlist specific
rules and so the community can reference rules in issues/PRs. IDs are
grouped by prefix:

| Prefix | Category |
|---|---|
| `OPSEC-xxx` | Operator OPSEC leaks (contact info, internal addresses, headers) |
| `INFRA-xxx` | Infrastructure disclosure (IP/hostname/certificate correlation) |
| `FP-xxx` | Fingerprinting / informational recording, not a leak by itself |
| `SEC-xxx` | Web application security (planned: TLS, headers hardening) |
| `CRED-xxx` | Credential / secret exposure (planned) |

## Implemented

| ID | Title | Severity | Analyzer |
|---|---|---|---|
| OPSEC-002 | Email address disclosed in page content | Medium | opsec |
| OPSEC-005 | Server software/version disclosure | Low | headers |
| OPSEC-006 | Missing recommended security headers | Info | headers |
| OPSEC-007 | Internal/private IP address referenced | Low | opsec |
| INFRA-001 | Possible IP address reference (needs correlation) | Medium (low confidence) | opsec |
| INFRA-002 | Possible origin infrastructure disclosure (correlated) | High | correlation |
| FP-001 | Response fingerprint recorded | Info | fingerprint |
| SEC-001 | TLS certificate issued to a clearnet hostname | High | tls |
| SEC-002 | Weak/deprecated TLS configuration | Medium | tls |
| OPSEC-004 | Debug/admin endpoint exposed | Low | robots |
| SEC-003 | JavaScript source map reference disclosed | Low | jsanalysis |
| OPSEC-009 | Build environment or local file paths disclosed in JavaScript | Low | jsanalysis |
| OPSEC-001 | External analytics/tracking script detected | Medium | external |
| INFRA-003 | External resources referenced in page content | Info | external |

## Planned (see docs/ROADMAP.md Phase 2/3 and the issue tracker)

| ID | Title |
|---|---|
| OPSEC-003 | Public EXIF metadata in uploaded images |
| OPSEC-008 | Cloud provider metadata endpoint reference |
| CRED-001 | API key or token pattern in page content or JS |
| CRED-002 | Private key header (`-----BEGIN ... PRIVATE KEY-----`) found |

## Contributing a new rule

1. Pick the right prefix and next free number.
2. Implement it inside an existing analyzer package, or create a new one
   under `internal/analyzer/<name>/` implementing the `Analyzer` interface.
3. Add the rule to this table.
4. Include a test with at least one true-positive and one true-negative
   fixture (see `docs/ROADMAP.md` Phase 1 testing item and
   `CONTRIBUTING.md`).
