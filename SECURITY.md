# Security Policy

## Supported Versions

OnionSec is currently in **early development (MVP phase)**. As such, only the latest version on the default branch is actively supported.

| Version        | Supported |
| -------------- | --------- |
| Latest (main)  | ✅         |
| Older versions | ❌         |

We recommend always using the most recent commit to ensure you have the latest fixes and improvements.

---

## Reporting a Vulnerability

If you discover a security vulnerability in OnionSec, please report it responsibly.

### How to Report

* Open a **private security advisory** (if available on the repository), OR
* Email the maintainer directly (if contact details are provided), OR
* Create an issue **without disclosing sensitive details publicly**

### What to Include

Please include as much information as possible:

* Description of the vulnerability
* Steps to reproduce
* Potential impact
* Suggested mitigation (if known)

---

## Scope

OnionSec is designed for:

* **Security observability of Tor `.onion` services**
* Detecting **accidental exposure of infrastructure, metadata, and configuration**
* Providing **evidence-based correlation of findings**

### Important

> ⚠️ OnionSec is intended **only for authorized use**.

* Do **NOT** scan onion services you do not own or lack permission to test
* The tool does **NOT aim to deanonymize services**
* Misuse may violate laws and ethical guidelines

---

## Security Considerations

### Tool Limitations

* Findings are based on **evidence, not proof**
* False positives may occur (e.g., regex-based detections)
* Correlation engine is still evolving (MVP phase)

### Safe Usage Practices

* Run scans only in **controlled environments**
* Avoid storing sensitive scan outputs insecurely
* Review reports before acting on findings
* Keep dependencies (Go, Tor, SQLite) updated

---

## Dependencies

OnionSec relies on:

* **Go (1.22+)**
* **Tor daemon** (SOCKS5 proxy)
* **SQLite (via CGO)**

Ensure these are securely configured and updated to avoid introducing vulnerabilities.

---

## Future Security Improvements

Planned enhancements include:

* Advanced analyzers (TLS, JS, source maps)
* Improved secret detection
* Stronger correlation engine
* Continuous monitoring and diffing
* API and dashboard with access controls

See `docs/ROADMAP.md` for more details.

---

## Responsible Disclosure

We appreciate responsible disclosure and will:

* Acknowledge receipt of your report
* Investigate and validate the issue
* Provide updates on resolution progress
* Credit reporters where appropriate (if desired)

---

## Disclaimer

OnionSec is a **defensive security tool**. The authors are not responsible for misuse or illegal activity conducted using this software.

Use it ethically and legally.
