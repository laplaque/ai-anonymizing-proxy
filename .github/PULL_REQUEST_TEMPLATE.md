# Pull Request

<!--
See CLAUDE.md for the full quality-gate spec.
Every section below is required. Empty checkboxes block merge; vague
"passes" assertions without evidence count as empty.
-->

## What

<!-- One paragraph: what changed and why. -->

## Changes

<!-- One bullet per file or logical change, with the why (not just the what). -->

-

## Quality Gates

Check each only after the gate is satisfied with concrete evidence. See `CLAUDE.md` for the full spec.

- [ ] `make check` passed locally (lint, test, security, vulncheck — all four sub-gates exit 0). Last line of output:
  `<paste>`
- [ ] `go test -race ./...` passed
- [ ] Coverage minimums met: 95% on `internal/anonymizer`, `internal/config`, `internal/anonymizer/packs`; 85% overall
- [ ] Delta coverage ≥95% on all changed/new files — see [Delta Coverage Report](#delta-coverage-report) below
- [ ] [§6 Test Inventory baseline-vs-head](#6-test-inventory--baseline-vs-head) completed below
- [ ] No hacks introduced (no `//nolint` without a substantive reason; no `t.Skip()` without a linked issue; no `// coverage-ignore`; no hardcoded values whose only purpose is to satisfy a specific test assertion; no new `gosec` exclusions — unless the exclusion is an explicit maintainer-authorized exception, declared both in the config with a substantive comment and in this PR body with a reference to the authorizing review)
- [ ] All CI jobs green at the PR head SHA

## Delta Coverage Report

Per `.github/scripts/delta-coverage.sh` — every function in changed/new `.go` source files (excluding `_test.go`, `_generated.go`, `mock_*`) must be ≥95%.

**Command:**

```bash
go test -race -coverprofile=coverage.out -covermode=atomic ./...
bash .github/scripts/delta-coverage.sh coverage.out 95.0 origin/main
```

**Raw script output** (paste verbatim — including the `Changed source files:` list, every per-FAIL line if any, and the final `SUCCESS:` / `ERROR:` line):

```text
<paste>
```

**Per-function table** — one row per scored function in every changed `.go` source file (a file the script reports as `UNSCORED` carries the alternate-evidence record described below instead of table rows):

| File | Function | Coverage % | ≥95% |
|---|---|---|---|
|  |  |  |  |

If any function is below 95%, do not open the PR — add tests until the gate passes. Never `// coverage-ignore` or suppress.

If the script reports `UNSCORED` files (no profile rows on this platform, e.g. a `GOOS`-tagged file), record the alternate evidence for each here: at minimum a clean cross-platform `go vet`/`go build`, plus a structural mapping of every function in the unscored file to the covered platform-neutral code it delegates to.

## §6 Test Inventory — baseline vs head

Method: checkout `main`, run `go test -race -count=1 -v <pkg>` and count `--- PASS` / `--- FAIL` lines (top-level + subtests). Repeat on the PR head SHA. Diff reasoning (e.g. "no `*_test.go` files touched") does NOT satisfy this gate — execution on both sides is required. See `docs/test-plans/ai-proxy-test-method.md` §6 for the inventory.

| Package | main (`<short sha>`) PASS / FAIL | head (`<short sha>`) PASS / FAIL | Delta |
|---|---|---|---|
| `./cmd/proxy/` | / | / |  |
| `./internal/anonymizer/` | / | / |  |
| `./internal/anonymizer/packs/` | / | / |  |
| `./internal/config/` | / | / |  |
| `./internal/domainmatch/` | / | / |  |
| `./internal/envfile/` | / | / |  |
| `./internal/logger/` | / | / |  |
| `./internal/management/` | / | / |  |
| `./internal/metrics/` | / | / |  |
| `./internal/mitm/` | / | / |  |
| `./internal/proxy/` | / | / |  |

Zero failures on either side. Any new failures, or net-negative deltas in PASS count, must be explained inline (with the failing/missing test names).

## Test Plan

<!-- Specific tests covering this change. Name the test functions; explain what each one pins. -->

-

## Linked Issues

Closes #
