# Contributing

Thanks for working on OnionSec. This project intentionally works through
GitHub Issues → PR → review → merge, one small piece at a time — see the
[open issues](../../issues), which are labeled by phase (`phase-1` …
`phase-5`) and type (`analyzer`, `core`, `docs`, `good-first-issue`).

## Workflow

1. Comment on (or self-assign) an issue before starting, so two people
   don't duplicate work.
2. Branch from `main`: `git checkout -b issue-<number>-short-description`.
3. Keep PRs scoped to one issue. Large PRs are hard to review and slow to
   merge.
4. `gofmt -w .` and `go vet ./...` before opening the PR.
5. Add or update tests for anything under `internal/`.
6. Open the PR referencing the issue (`Closes #<number>`).

## Adding a new analyzer

Analyzers are the easiest way to contribute. Steps:

1. Create `internal/analyzer/<name>/<name>.go`.
2. Implement the two-method `analyzer.Analyzer` interface
   (`internal/analyzer/analyzer.go`):
   ```go
   type Analyzer interface {
       Name() string
       Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error)
   }
   ```
3. Give every Finding you emit a stable rule ID (see `docs/RULES.md` and
   `docs/RULE_CONTRIBUTIONS.md` for prefix allocation and proposing new ranges)
   and add it to that table.
4. Prefer emitting **evidence with honest confidence** over a single
   high-confidence Finding from one weak signal — see
   `docs/ARCHITECTURE.md` "Why evidence-first."
5. Register it in `internal/scan/scan.go`'s `DefaultRegistry()`.
6. Add a table-driven test with at least one true-positive and one
   true-negative fixture.

## Code style

- Standard `gofmt`. No linters beyond `go vet` are required yet (an issue
  tracks adding `golangci-lint` in CI once the analyzer set stabilizes).
- Keep the module dependency-free where reasonably possible — see
  `docs/ARCHITECTURE.md` for why. If a change genuinely needs an external
  dependency, say so in the PR description and it'll be discussed there.

## Safety review

Any change touching the crawler, Tor client, or anything that parses
untrusted target content gets an extra look against
`docs/ARCHITECTURE.md`'s "Safety rules" section (resource limits,
same-origin only, never executing target JS). Flag this explicitly in
your PR description if it applies.

## Reporting a security issue in OnionSec itself

Please don't open a public issue for a vulnerability in OnionSec itself
(as opposed to a scanning rule). Open a private security advisory via the
repository's "Security" tab instead.
