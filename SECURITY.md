# Security Policy

The OnionSec team takes the security of our auditing tools and users seriously. This document details our supported versions, vulnerability reporting procedures, and disclosure timeline expectations.

---

## 1. Supported Versions

Security patches and bug fixes are prioritized for the following versions of OnionSec:

| Version / Branch | Supported          | Notes |
| ---------------- | ------------------ | ----- |
| `main`           | :white_check_mark: | Actively developed trunk; receives direct security patches. |
| Latest Tag (`v0.x`) | :white_check_mark: | Latest release tags receive patch updates for critical vulnerabilities. |
| `< v0.1.0` (Scaffold) | :x:                | Deprecated initial scaffold commits. |

Users and operators are strongly encouraged to keep their installations updated to the latest commit on `main` or the latest published release.

---

## 2. Reporting a Vulnerability

**Please do not report security vulnerabilities in OnionSec through public GitHub issues, discussions, or pull requests.**

### Preferred Method: GitHub Private Security Advisory
To submit a confidential vulnerability report:
1. Navigate to the **Security** tab of the repository: [Security Advisories](https://github.com/AryanXCode646/OnionScan/security/advisories).
2. Click **Report a vulnerability** to open a private advisory draft.
3. Provide a thorough summary of the issue:
   - **Component Affected**: (e.g., crawler, Tor proxy client, HTTP API server `onionsecd`, credential analyzer, SQLite storage).
   - **Vulnerability Type**: (e.g., SSRF, memory exhaustion, unredacted credential leakage, remote code execution).
   - **Steps to Reproduce**: Detailed reproduction steps or minimal proof-of-concept (PoC). Please sanitize all test fixtures and avoid using live sensitive credentials or active onion addresses.
   - **Potential Impact**: An honest assessment of the exploitability and security blast radius.

---

## 3. Disclosure Timeline Expectations

We adhere to standard **Coordinated Vulnerability Disclosure (CVD)** principles:

| Milestone | Target Response Window |
|---|---|
| **Initial Acknowledgment** | Within **48 to 72 hours** of report receipt. |
| **Triage & Validation** | Within **7 business days** to confirm reproducibility and determine CVSS severity. |
| **Patch Development & Testing** | Within **14 to 30 days** depending on vulnerability complexity. |
| **Public Release & Advisory** | Coordinated with the finder upon release of the fix, with a standard **90-day maximum** embargo. |

### Credit and Acknowledgement
Security researchers who responsibly disclose vulnerabilities in OnionSec will be credited in the GitHub Security Advisory release notes and project changelog (unless anonymity is requested).

---

## 4. Scope and Exclusions

### In Scope
- Vulnerabilities within the OnionSec codebase itself:
  - `cmd/onionsec` (CLI application)
  - `cmd/onionsecd` (HTTP API daemon)
  - `internal/` (crawler engine, storage, correlation, diffing, analyzers)
  - `web/` (React/Next.js dashboard)
- Denial-of-service vulnerabilities caused by malicious HTML/JS target inputs exhausting memory or CPU beyond configured limits.
- Bypasses of crawler safety rules (such as same-origin escapes or unredacted credential leaks into logs or persistent storage).

### Out of Scope
- Security vulnerabilities in scanned third-party Tor hidden services. (OnionSec is an authorized security scanner; findings identified on external target onions belong to those service operators).
- Attacks requiring physical access to the auditor's local machine or root compromise of the host running `onionsecd`.
- Denial-of-service attacks directed against public Tor relays or the Tor network itself.
- Social engineering attacks targeting project maintainers.
