# AI Anonymizing Proxy

MITM proxy that strips PII from requests to LLM APIs before they leave the machine.

## Invariants

- **No PII leaves the process.** Re-hydration happens in local memory only.
- **No real PII in tests or fixtures.** Synthetic, checksum-valid values only.
- **Pack order matters.** `enabledPacks` order determines pattern evaluation order; SECRETS must precede GLOBAL (issue #70).

## Quality Gates

Every PR must satisfy all of these before merge.

- **`make check` passes locally** — aggregates `lint`, `test`, `security`, `vulncheck`; all four sub-gates exit 0.
- **`go test -race ./...` passes** — including `TestTokenFormatNonRetriggering` for every PII type.
- **Coverage minimums:** 95% on `internal/anonymizer`, `internal/config`, `internal/anonymizer/packs`; 85% overall.
- **Delta coverage:** 95% on all changed/new files (enforced via `.github/scripts/delta-coverage.sh` at threshold 95.0 in the CI Test job).
- **Test-plan inventory baseline-vs-head.** Execute the `docs/test-plans/` inventory on `main` AND on the PR head SHA. Document per-package PASS/FAIL counts in the PR body under a `## §6 Test Inventory — baseline vs head` section. Diff reasoning ("no test files touched") does NOT satisfy this gate. See `docs/test-plans/ai-proxy-test-method.md` §6 for the inventory.
- **No hacks.** Never add code whose purpose is to make a check pass rather than to make the code correct — including `//nolint` directives that suppress disabled linters or lack a substantive reason comment, `t.Skip()` without a linked issue, hardcoded values to satisfy a specific test assertion, or `// coverage-ignore` annotations. If the correct fix is unclear, ask before merging.
