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
| FP-002 | API endpoint pattern detected | Info | apidetect |
| CRED-001 | API key or token pattern disclosed | High | credentials |
| CRED-002 | Private key header disclosed | Critical | credentials |
| OPSEC-003 | Public EXIF metadata in uploaded images | Low / High | metadata |
| INFRA-004 | Shared infrastructure or identity correlated across multiple targets | High | correlation |

## Planned (see docs/ROADMAP.md Phase 2/3 and the issue tracker)

| ID | Title |
|---|---|
| OPSEC-008 | Cloud provider metadata endpoint reference |

## Contributing a new rule

For comprehensive guidelines on proposing brand-new rule categories, reserving prefix namespaces, and avoiding ID collisions across concurrent PRs, see [`docs/RULE_CONTRIBUTIONS.md`](RULE_CONTRIBUTIONS.md).

Quick summary:
1. **Existing Category**: Check the table above for the highest sequential ID and verify open PRs to claim the next free number.
2. **New Category / Range**: Open an RFC proposal issue with title `[Rule Category Proposal]: <Category> (<PREFIX>-xxx)` to pre-allocate the prefix before starting implementation.
3. **Implementation**: Implement the rule inside an existing analyzer or create a new package under `internal/analyzer/<name>/` implementing the `analyzer.Analyzer` interface.
4. **Testing**: Include unit tests with at least one true-positive and one true-negative fixture.
5. **Documentation**: Add the rule to this table in your PR.

