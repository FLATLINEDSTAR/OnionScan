# Community Rule Contribution Process

This guide outlines how to contribute new detection rules and analyzer categories to OnionSec, with a specific focus on reserving rule ID ranges to prevent collisions across concurrent pull requests.

---

## 1. Rule Identification Philosophy

Every finding emitted by OnionSec has a permanent, stable `ID` (such as `OPSEC-001`, `SEC-001`, or `CRED-001`). Stable rule IDs are critical because they allow:
1. Operators to suppress or allowlist specific rules in YAML configuration.
2. The monitoring engine (`onionsec monitor` / `onionsec diff`) to reliably track introduced, resolved, and persisting issues across scan intervals.
3. The HTTP API and web dashboard to group, filter, and track security findings consistently.
4. Security researchers and operators to reference findings unambiguously in reports and public discussions.

---

## 2. Existing Categories & Active Prefixes

Before proposing a new rule, verify if your detection logic fits within an existing registered category in [`docs/RULES.md`](RULES.md):

| Prefix | Category | Scope |
|---|---|---|
| `OPSEC-xxx` | Operator OPSEC Leaks | Leaks of operator identity, email addresses, server banner software versions, exposed admin panels, build paths, internal addresses. |
| `INFRA-xxx` | Infrastructure Disclosure | IP address disclosures, clearnet resource references, cross-target infrastructure correlation. |
| `FP-xxx` | Fingerprinting | Informational signatures, technology stack identification, API endpoint detection patterns (non-leaks by themselves). |
| `SEC-xxx` | Web & Transport Security | Weak or invalid TLS configurations, clearnet TLS certificates, source map exposure, security header deficiencies. |
| `CRED-xxx` | Credential & Secret Exposure | Hardcoded API keys, private keys, authentication tokens, connection credentials. |

---

## 3. Contributing a Rule to an Existing Category

If your proposed detection fits into an existing category:

1. **Find the Next Available ID**:
   - Check the table in [`docs/RULES.md`](RULES.md).
   - Search open pull requests (`gh pr list --search "<PREFIX>-"`) to ensure no in-flight PR is using the same number.
   - Take the next sequential integer (e.g., if `OPSEC-009` is the highest, claim `OPSEC-010`).
2. **Implement Detection Logic**:
   - Add your rule check to the appropriate package under `internal/analyzer/<category>/`.
   - Never log or store raw secrets unredacted (use redaction helpers for `CRED-xxx`).
   - Calibrate confidence honestly (0.0 to 1.0) rather than artificially inflating scores.
3. **Write Table-Driven Tests**:
   - Every rule must have unit tests covering at least one true-positive and one true-negative fixture.
4. **Update Documentation**:
   - Add your new rule entry to the table in `docs/RULES.md` within your PR.

---

## 4. Proposing a Brand-New Rule Category & Prefix

When adding a novel analyzer domain (for example, WebSockets, DNS/DoH leaks, Content Security Policy analysis, or Cryptographic validation) that does not cleanly fit existing prefixes, follow this reservation workflow to avoid collisions across concurrent PRs.

### Step 1: Open a Rule Proposal Issue
Before writing code, open a GitHub issue with the title format:
```
[Rule Category Proposal]: <Category Name> (<PREFIX>-xxx)
```
Include the following details:
- **Proposed Prefix**: 3–5 uppercase alphanumeric characters (e.g., `CSP-`, `WS-`, `CRYPTO-`).
- **Category Scope**: What threats or disclosures will this category cover? Why doesn't it fit into `OPSEC-`, `SEC-`, or `INFRA-`?
- **Initial Rule Range**: Specify initial rules to be introduced (e.g., `001` through `005`).
- **Proposed Analyzer Package**: Proposed location in `internal/analyzer/<name>/`.

### Step 2: Maintainer Pre-Allocation / Claim
A maintainer will review the prefix proposal. Once approved:
- The issue will receive the `rule-approved` label.
- A quick prefix reservation commit or comment will record the prefix in `docs/RULES.md` under the "Reserved Categories" table.
- This reserves the prefix namespace and prevents duplicate claims by other contributors.

### Step 3: Collision Resolution Policy
In the rare event that two contributors open concurrent PRs using the same prefix or ID:
- **First-Merged Precedence**: The PR merged first retains the allocated ID.
- **Automated Renumbering Requirement**: The second PR author will be requested during review to renumber their rule to the next unused sequence number. Rule IDs should never be reused or re-assigned once merged to `main`.

---

## 5. Analyzer Implementation Guidelines & Quality Standards

All new analyzers and rules must adhere to the core architectural invariants:

1. **Standard Library Preference**: Avoid external dependencies. Standard library packages (`net/http`, `crypto/tls`, `regexp`, `encoding/json`, `strings`) should be used wherever possible.
2. **Safe Parsing of Untrusted Input**:
   - Target responses are completely untrusted.
   - Never execute target JavaScript or evaluate untrusted code.
   - Respect crawler limits (`MaxBodyByte`, timeouts, same-origin restrictions).
3. **Secret Redaction**:
   - Analyzers inspecting credentials (`CRED-xxx`) must mask tokens (e.g., `sk_live_****[REDACTED]`).
   - Never index raw secrets into the bipartite evidence store (`internal/storage`).
4. **Calibrated Confidence**:
   - High confidence (0.9–1.0) is reserved for definitive, unambiguous disclosures.
   - Heuristics, regex approximations, or single header signals must use Medium (0.5–0.7) or Low (0.2–0.4) confidence until correlated by `internal/correlation`.

---

## 6. Implementation Checklist for PRs

Use this checklist when submitting your rule PR:

- [ ] Rule ID verified against `docs/RULES.md` and in-flight PRs.
- [ ] Analyzer implements `analyzer.Analyzer` interface (`Name()`, `Analyze()`).
- [ ] Analyzer registered in `internal/scan/scan.go` (`DefaultRegistry()`).
- [ ] Comprehensive unit tests with true-positive and true-negative cases (`go test -v ./internal/analyzer/...`).
- [ ] No formatting issues (`test -z "$(gofmt -l .)"`) and no vet errors (`go vet ./...`).
- [ ] Added rule entry to `docs/RULES.md`.
- [ ] PR references the issue (`Closes #<issue-number>`).
