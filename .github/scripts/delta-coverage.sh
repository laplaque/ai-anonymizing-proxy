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

# Get changed .go source files (exclude tests, generated, mocks)
changed_files=$(git diff --name-only --diff-filter=ACMR "${BASE_REF}...HEAD" -- '*.go' \
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
  while IFS= read -r line; do
    # Extract coverage percentage (last field, strip %)
    pct=$(echo "$line" | awk '{print $NF}' | tr -d '%')
    func_name=$(echo "$line" | awk '{print $(NF-1)}')

    # Skip the total line
    if [ "$func_name" = "(statements)" ]; then
      continue
    fi

    checked=$((checked + 1))

    # Compare using awk for float comparison
    below=$(awk "BEGIN {print ($pct < $THRESHOLD) ? 1 : 0}")
    if [ "$below" -eq 1 ]; then
      echo "FAIL: ${line}"
      failed=$((failed + 1))
    fi
  done < <(echo "$cover_output" | grep -F "/$file:" || true)
done <<< "$changed_files"

echo ""
echo "Checked ${checked} functions in ${changed_files_count} changed files."

if [ "$failed" -gt 0 ]; then
  echo "ERROR: ${failed} function(s) below ${THRESHOLD}% coverage threshold."
  exit 1
fi

echo "SUCCESS: All functions in changed files meet ${THRESHOLD}% coverage threshold."
