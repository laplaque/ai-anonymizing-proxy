#!/bin/bash
set -euo pipefail

# update-benchmark-gist.sh — update shields.io badge data in a GitHub gist
#
# Usage: update-benchmark-gist.sh <benchmark-file> <gist-id>
# Requires: BENCHMARK_GIST_TOKEN env var (PAT with gist scope)

BENCH_FILE="${1:-.tmp/benchmark-ci.txt}"
GIST_ID="${2:?ERROR: gist ID required as second argument}"

if [ ! -f "$BENCH_FILE" ]; then
  echo "ERROR: benchmark file not found: $BENCH_FILE" >&2
  exit 1
fi

if [ -z "${BENCHMARK_GIST_TOKEN:-}" ]; then
  echo "ERROR: BENCHMARK_GIST_TOKEN not set" >&2
  exit 1
fi

REGEX_CACHE_THRESHOLD=2500000
STREAMING_THRESHOLD=20000000

regex_worst=0
streaming_worst=0

while IFS= read -r line; do
  if [[ $line =~ ^(Benchmark[A-Za-z]+)-[0-9]+[[:space:]]+[0-9]+[[:space:]]+([0-9]+) ]]; then
    name="${BASH_REMATCH[1]}"
    ns_op="${BASH_REMATCH[2]}"

    case "$name" in
      BenchmarkStreaming*)
        if [ "$ns_op" -gt "$streaming_worst" ]; then
          streaming_worst=$ns_op
        fi
        ;;
      *)
        if [ "$ns_op" -gt "$regex_worst" ]; then
          regex_worst=$ns_op
        fi
        ;;
    esac
  fi
done < "$BENCH_FILE"

# Format display values
format_us() {
  local ns=$1
  if [ "$ns" -ge 1000000 ]; then
    echo "$(echo "scale=2; $ns / 1000000" | bc)ms"
  elif [ "$ns" -ge 1000 ]; then
    echo "$(echo "scale=1; $ns / 1000" | bc)us"
  else
    echo "${ns}ns"
  fi
}

regex_display="$(format_us "$regex_worst") / 2.5ms"
streaming_display="$(format_us "$streaming_worst") / 20ms"

# Determine badge color based on headroom
badge_color() {
  local actual=$1 threshold=$2
  local headroom=$(( (threshold - actual) * 100 / threshold ))
  if [ "$actual" -gt "$threshold" ]; then
    echo "red"
  elif [ "$headroom" -lt 20 ]; then
    echo "yellow"
  else
    echo "brightgreen"
  fi
}

regex_color=$(badge_color "$regex_worst" "$REGEX_CACHE_THRESHOLD")
streaming_color=$(badge_color "$streaming_worst" "$STREAMING_THRESHOLD")

# Build gist payload
PAYLOAD=$(cat << JSONEOF
{
  "files": {
    "benchmark-regex-cache.json": {
      "content": "{ \"schemaVersion\": 1, \"label\": \"regex / cache\", \"message\": \"${regex_display}\", \"color\": \"${regex_color}\" }"
    },
    "benchmark-streaming.json": {
      "content": "{ \"schemaVersion\": 1, \"label\": \"streaming\", \"message\": \"${streaming_display}\", \"color\": \"${streaming_color}\" }"
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

echo "Gist ${GIST_ID} updated: regex/cache=${regex_display} (${regex_color}), streaming=${streaming_display} (${streaming_color})"
