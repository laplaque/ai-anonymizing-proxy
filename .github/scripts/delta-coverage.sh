#!/bin/bash
set -euo pipefail

# delta-coverage.sh — fail if any function in changed .go files is below threshold
#
# Usage: delta-coverage.sh <coverage-profile> <threshold> <base-ref>
# Example: delta-coverage.sh coverage.out 95.0 origin/main

COVERAGE_FILE="${1:?ERROR: coverage profile required as first argument}"
THRESHOLD="${2:?ERROR: threshold percentage required as second argument}"
BASE_REF="${3:?ERROR: base ref required as third argument}"

if [ ! -f "$COVERAGE_FILE" ]; then
  echo "ERROR: coverage file not found: $COVERAGE_FILE" >&2
  exit 1
fi

# Get changed .go source files (exclude tests, generated, mocks).
# Fail closed: if `git diff` cannot resolve the merge base (e.g. shallow clone
# without enough history), we MUST exit non-zero so the CI job fails loudly
# rather than silently bypassing the delta gate.
if ! diff_output=$(git diff --name-only --diff-filter=ACMR "${BASE_REF}...HEAD" -- '*.go'); then
  echo "ERROR: git diff failed against ${BASE_REF}...HEAD — cannot compute changed files." >&2
  echo "  Check that the workflow's actions/checkout step uses fetch-depth: 0 so the merge base is reachable." >&2
  exit 1
fi

changed_files=$(echo "$diff_output" \
  | grep -v '_test\.go$' \
  | grep -v '_generated\.go$' \
  | grep -v 'mock_' \
  || true)

if [ -z "$changed_files" ]; then
  echo "No changed Go source files — delta coverage check skipped."
  exit 0
fi

echo "=== Delta Coverage Check (threshold: ${THRESHOLD}%) ==="
echo ""
changed_files_count=$(echo "$changed_files" | wc -l)

echo "Changed source files:"
echo "$changed_files" | sed 's/^/  /'
echo ""

# Per-function coverage from the parsed source. funccoverage assigns a profile
# block to a function only when the block lies within the function's
# line/column extent (the rule `go tool cover -func` uses), so blocks of
# package-level function literals never count toward a neighboring
# declaration. Fail closed if the helper cannot be built, a file cannot be
# parsed, or a changed file built on this platform has no blocks in the
# profile (its package was left out of the coverage run). The helper lives in
# tools/funccoverage so that ./... covers and gates it too.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_SRC="$SCRIPT_DIR/../../tools/funccoverage"
helper_dir="$(mktemp -d)"
trap 'rm -rf "$helper_dir"' EXIT
if ! (cd "$HELPER_SRC" && go build -o "$helper_dir/funccoverage" .); then
  echo "ERROR: failed to build $HELPER_SRC" >&2
  exit 1
fi
mapfile -t changed_list <<< "$changed_files"
if ! func_rows=$("$helper_dir/funccoverage" "$COVERAGE_FILE" "${changed_list[@]}"); then
  echo "ERROR: funccoverage failed for the changed files." >&2
  exit 1
fi

failed=0
checked=0
skipped=0

# Each row: <file>:<line> TAB <name> TAB <covered stmts> TAB <total stmts>.
while IFS=$'\t' read -r location func_name covered total; do
  if [ -z "$location" ]; then
    continue
  fi

  # A function whose extent holds no profile block has no statements (an
  # empty body, such as an interface-compliance method), so it has nothing
  # to cover: 0 of 0 is not a failure. The only other source of 0 is a file
  # that build constraints exclude on this platform, which funccoverage
  # names in a warning; any other uninstrumented file already failed above.
  if [ "$total" -eq 0 ]; then
    skipped=$((skipped + 1))
    continue
  fi

  checked=$((checked + 1))

  pct=$(awk -v c="$covered" -v t="$total" 'BEGIN {printf "%.1f", 100 * c / t}')
  below=$(awk -v c="$covered" -v t="$total" -v th="$THRESHOLD" 'BEGIN {print (100 * c / t < th) ? 1 : 0}')
  if [ "$below" -eq 1 ]; then
    echo "FAIL: ${location}: ${func_name} ${pct}% (${covered}/${total} statements)"
    failed=$((failed + 1))
  fi
done <<< "$func_rows"

echo ""
echo "Checked ${checked} functions in ${changed_files_count} changed files (${skipped} without statements skipped)."

if [ "$failed" -gt 0 ]; then
  echo "ERROR: ${failed} function(s) below ${THRESHOLD}% coverage threshold."
  exit 1
fi

echo "SUCCESS: All functions in changed files meet ${THRESHOLD}% coverage threshold."
