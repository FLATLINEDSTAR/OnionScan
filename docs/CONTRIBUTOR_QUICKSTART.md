# Contributor Quickstart Guide

This guide is a hands-on quickstart for developers and security researchers looking to contribute code, detection rules, or documentation to OnionSec.

---

> ⚠️ **Authorized & Defensive Use Notice**
> OnionSec is designed strictly for defensive security observability, exposure auditing, and configuration leak detection. Only scan onion services that you own or have explicit, documented authorization to test. Never target third-party hidden services without permission.

---

## 1. Prerequisites

Ensure the following tools are installed on your workstation before starting:

| Tool | Minimum Version | Required For | Installation / Verification |
|---|---|---|---|
| **Go** | 1.22+ | Core scanner, CLI, API daemon, tests | `go version` ([Install Go](https://go.dev/dl/)) |
| **C Compiler (CGO)** | GCC 9+ or Clang 10+ | SQLite storage engine (`mattn/go-sqlite3`) | `gcc --version` or `clang --version` |
| **Git** | 2.25+ | Version control & branch management | `git --version` |
| **Tor Daemon** | 0.4.5+ *(optional)* | Live scanning against `.onion` targets | `tor --version` (SOCKS5 on `127.0.0.1:9050`) |
| **Node.js & npm** | Node 20+ *(optional)* | Web dashboard development in `web/` | `node -v && npm -v` |

> **Note:** A running Tor instance is **not** required to build the binaries or run the test suite. All network-facing unit tests utilize internal mock SOCKS5 proxies.

---

## 2. Repository Setup

### Fork and Clone

1. Fork [`FLATLINEDSTAR/OnionScan`](https://github.com/FLATLINEDSTAR/OnionScan) to your personal GitHub account.
2. Clone your fork locally and configure remotes:

```bash
# Clone your fork
git clone https://github.com/<your-username>/OnionScan.git
cd OnionScan

# Add the upstream repository
git remote add upstream https://github.com/FLATLINEDSTAR/OnionScan.git

# Verify remote configuration
git remote -v

# Fetch the latest upstream branches
git fetch upstream
```

---

## 3. Build Instructions

OnionSec includes two primary Go binaries: the CLI (`cmd/onionsec`) and the API daemon (`cmd/onionsecd`). Because the persistence layer uses SQLite, `CGO_ENABLED=1` is required (enabled by default when a C compiler is present).

### Build CLI and Daemon

```bash
# Build the onionsec CLI binary
go build -o onionsec ./cmd/onionsec

# Build the onionsecd daemon binary
go build -o onionsecd ./cmd/onionsecd

# Build all packages across the repository
go build ./...
```

### Verify Binaries

```bash
# Check CLI version and help text
./onionsec version
./onionsec --help

# Check daemon flags
./onionsecd -h
```

### Build Web Dashboard (Optional)

If contributing to the frontend located in `web/`:

```bash
cd web
npm ci
npm run build
cd ..
```

---

## 4. Test & Verification Instructions

Before submitting changes, run the local verification suite to ensure all tests, formatting, and static analysis checks pass.

### Quick Verification Checklist

```bash
# 1. Verify code formatting conforms to Go standards
test -z "$(gofmt -l .)"

# Automatically fix formatting issues if any exist
gofmt -w .

# 2. Run Go static analysis
go vet ./...

# 3. Run entire test suite with race detector enabled
go test -v -race ./...
```

### Running Targeted Tests

When working on a specific subsystem, you can run targeted package tests:

```bash
# Tor SOCKS5 client tests (uses mock SOCKS5 server)
go test -v -race ./internal/tor/...

# Modular analyzers tests
go test -v -race ./internal/analyzer/...

# Evidence store & SQLite tests
go test -v -race ./internal/storage/...

# Risk scoring and deduplication tests
go test -v -race ./internal/risk/...

# REST API daemon tests
go test -v -race ./internal/api/...
```

---

## 5. Development Workflow

### 1. Create a Topic Branch

Always create a dedicated topic branch branched from the latest `upstream/main`:

```bash
git fetch upstream
git checkout -b <prefix>/<short-description> upstream/main
```

Common branch prefixes:
- `feat/` — New feature, command, or analyzer
- `fix/` — Bug fix or error handling correction
- `docs/` — Documentation updates or additions
- `test/` — Adding or improving test cases
- `refactor/` — Code refactoring without behavior change

### 2. Follow Commit Standards

We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```text
<type>(<scope>): <short summary in imperative mood>

[optional detailed description of problem and solution]

[optional footer: Closes #<issue-number>]
```

Examples:
- `feat(analyzer): add weak cipher suite detection`
- `fix(storage): ensure foreign key enforcement on sqlite connections`
- `docs: add contributor quickstart guide`

---

## 6. Submitting a Contribution

Once changes are tested and verified locally:

```bash
# 1. Verify diff and ensure no untracked or temporary files
git status
git diff --check
git diff

# 2. Rebase onto latest upstream main
git fetch upstream
git rebase upstream/main

# 3. Push topic branch to your fork
git push -u origin <prefix>/<short-description>
```

Then open a Pull Request against `FLATLINEDSTAR/OnionScan:main`:
1. Use a clear, concise title following Conventional Commits.
2. Fill out all sections in the pull request template (summary, motivation, test results).
3. Confirm that CI passes on GitHub Actions.

---

## 7. Common Setup & Troubleshooting

### CGO and SQLite Build Errors

**Symptom:**
`Binary was compiled without CGO support` or `gcc: command not found` when building or running storage tests.

**Resolution:**
OnionSec relies on `github.com/mattn/go-sqlite3`, which requires CGO.
- **Ubuntu/Debian:** `sudo apt-get install build-essential`
- **Fedora/RHEL:** `sudo dnf groupinstall "Development Tools"`
- **macOS:** `xcode-select --install`
- Ensure `CGO_ENABLED=1` in your environment (`go env CGO_ENABLED`).

### Tor Proxy Connection Refused During Live Scans

**Symptom:**
`dial socks5 127.0.0.1:9050: connect: connection refused` when running `./onionsec scan <target>.onion`.

**Resolution:**
- Verify your local Tor service is running:
  ```bash
  # Linux systemd
  sudo systemctl status tor
  sudo systemctl start tor

  # macOS Homebrew
  brew services status tor
  brew services start tor
  ```
- Test Tor connectivity through the proxy:
  ```bash
  curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
  ```
- If your Tor instance runs on a custom SOCKS port, configure it via CLI flag or config:
  ```bash
  ./onionsec scan target.onion --config custom-config.yaml
  # Or with onionsecd:
  ./onionsecd -socks 127.0.0.1:9150
  ```

### Database Permissions and File Locks

**Symptom:**
`attempt to write a readonly database` or `database is locked`.

**Resolution:**
- The default SQLite database path is `~/.onionsec/onionsec.db`.
- Ensure the `~/.onionsec` directory exists and is writable by your user:
  ```bash
  mkdir -p ~/.onionsec
  chmod 700 ~/.onionsec
  ```
- Use a dedicated test database path when running multiple instances or concurrent daemon instances:
  ```bash
  ./onionsecd -db /tmp/test-onionsec.db
  ```

---

## 8. Further Reading

- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — Full contribution guidelines and analyzer interface details.
- [`docs/API.md`](API.md) — HTTP API endpoints and schema specification.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — System architecture, crawler mechanics, and correlation pipeline.
- [`docs/RULES.md`](RULES.md) — Detection rule definitions and category catalog.
- [`docs/RULE_CONTRIBUTIONS.md`](RULE_CONTRIBUTIONS.md) — Process for proposing and reserving new rule IDs.
