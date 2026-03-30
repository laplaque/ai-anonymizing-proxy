#!/bin/bash
set -euo pipefail

# update-coverage-gist.sh — update shields.io coverage badge data in a GitHub gist
#
# Usage: update-coverage-gist.sh <coverage-file> <gist-id>
# Requires: BENCHMARK_GIST_TOKEN env var (PAT with gist scope)

COVERAGE_FILE="${1:?ERROR: coverage file required as first argument}"
GIST_ID="${2:?ERROR: gist ID required as second argument}"

if [ ! -f "$COVERAGE_FILE" ]; then
  echo "ERROR: coverage file not found: $COVERAGE_FILE" >&2
  exit 1
fi

if [ -z "${BENCHMARK_GIST_TOKEN:-}" ]; then
  echo "ERROR: BENCHMARK_GIST_TOKEN not set" >&2
  exit 1
fi

# Extract total coverage percentage from go tool cover -func output
# Last line is: total:  (statements)  XX.X%
COVERAGE=$(go tool cover -func="$COVERAGE_FILE" | grep '^total:' | awk '{print $NF}' | tr -d '%')

if [ -z "$COVERAGE" ]; then
  echo "ERROR: could not parse coverage from $COVERAGE_FILE" >&2
  exit 1
fi

# Determine badge color
# green >= 85, yellow >= 70, red < 70
COLOR="red"
if [ "$(echo "$COVERAGE >= 85" | bc -l)" -eq 1 ]; then
  COLOR="brightgreen"
elif [ "$(echo "$COVERAGE >= 70" | bc -l)" -eq 1 ]; then
  COLOR="yellow"
fi

DISPLAY="${COVERAGE}%"

# Build gist payload
PAYLOAD=$(cat << JSONEOF
{
  "files": {
    "coverage.json": {
      "content": "{ \"schemaVersion\": 1, \"label\": \"coverage\", \"message\": \"${DISPLAY}\", \"color\": \"${COLOR}\" }"
    }
  }
}
JSONEOF
)

# Update gist via GitHub API
curl -sf -X PATCH \
  -H "Authorization: token ${BENCHMARK_GIST_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -d "$PAYLOAD" \
  "https://api.github.com/gists/${GIST_ID}" > /dev/null

echo "Gist ${GIST_ID} updated: coverage=${DISPLAY} (${COLOR})"
