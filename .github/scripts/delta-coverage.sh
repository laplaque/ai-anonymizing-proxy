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

# Get function-level coverage
cover_output=$(go tool cover -func="$COVERAGE_FILE")

failed=0
checked=0

while IFS= read -r file; do
  # Match file path precisely using literal match with trailing colon
  # to prevent substring collisions (e.g. proxy.go matching reverse_proxy.go).
  file_funcs=$(echo "$cover_output" | grep -F "/$file:" || true)
  # Declaration lines of every function in this file, ascending. A function's
  # source range runs from its declaration line up to the next one.
  func_starts=$(echo "$file_funcs" | awk -F: 'NF > 2 {print $2}' | sort -n)
  while IFS= read -r line; do
    # A changed file with no functions yields one empty line.
    if [ -z "$line" ]; then
      continue
    fi

    # Extract coverage percentage (last field, strip %)
    pct=$(echo "$line" | awk '{print $NF}' | tr -d '%')
    func_name=$(echo "$line" | awk '{print $(NF-1)}')

    # Skip the total line
    if [ "$func_name" = "(statements)" ]; then
      continue
    fi

    # `go tool cover -func` reports 0.0% for functions with zero instrumented
    # statements (e.g. empty interface-compliance methods). That's not a
    # coverage failure — it's a 0-of-0 ratio. Detect by summing numStmts from
    # all blocks in the raw profile that start inside the function's source
    # range (its declaration line up to, not including, the next function's).
    # If the sum is 0, the function has nothing to cover.
    #
    # The range is needed because block start positions differ by toolchain:
    # go1.26 starts a function's first block at the opening brace on the
    # declaration line, go1.27 at the first statement on a later line. Matching
    # only the declaration line found no block under go1.27, and grep's
    # no-match exit status then aborted this script silently under pipefail.
    func_start_line=$(echo "$line" | awk -F: '{print $2}')
    next_start_line=$(echo "$func_starts" \
      | awk -v s="$func_start_line" '$1 > s {print $1; exit}')
    stmt_sum=$(awk -v f="/${file}:" -v lo="$func_start_line" -v hi="${next_start_line:-0}" '
      {
        i = index($1, f)
        if (i == 0) next
        split(substr($1, i + length(f)), pos, ".")
        l = pos[1] + 0
        if (l >= lo && (hi == 0 || l < hi)) sum += $2
      }
      END {print sum+0}' "$COVERAGE_FILE")
    if [ "$stmt_sum" = "0" ]; then
      continue
    fi

    checked=$((checked + 1))

    # Compare using awk for float comparison
    below=$(awk "BEGIN {print ($pct < $THRESHOLD) ? 1 : 0}")
    if [ "$below" -eq 1 ]; then
      echo "FAIL: ${line}"
      failed=$((failed + 1))
    fi
  done <<< "$file_funcs"
done <<< "$changed_files"

echo ""
echo "Checked ${checked} functions in ${changed_files_count} changed files."

if [ "$failed" -gt 0 ]; then
  echo "ERROR: ${failed} function(s) below ${THRESHOLD}% coverage threshold."
  exit 1
fi

echo "SUCCESS: All functions in changed files meet ${THRESHOLD}% coverage threshold."
