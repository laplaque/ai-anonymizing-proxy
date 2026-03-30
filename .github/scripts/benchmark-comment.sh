#!/bin/bash
set -euo pipefail

# benchmark-comment.sh — parse benchmark results and format a PR comment
#
# Usage: benchmark-comment.sh <benchmark-file>
# Output: markdown table on stdout

BENCH_FILE="${1:-.tmp/benchmark-ci.txt}"

if [ ! -f "$BENCH_FILE" ]; then
  echo "ERROR: benchmark file not found: $BENCH_FILE" >&2
  exit 1
fi

REGEX_CACHE_THRESHOLD=2500000
STREAMING_THRESHOLD=20000000

echo '## Benchmark results'
echo ''
echo '| Benchmark | ns/op | Budget | Headroom | Status |'
echo '|-----------|------:|-------:|---------:|--------|'

while IFS= read -r line; do
  if [[ $line =~ ^(Benchmark[A-Za-z]+)-[0-9]+[[:space:]]+[0-9]+[[:space:]]+([0-9]+) ]]; then
    name="${BASH_REMATCH[1]}"
    ns_op="${BASH_REMATCH[2]}"

    case "$name" in
      BenchmarkStreaming*)
        threshold=$STREAMING_THRESHOLD
        budget_label="20ms"
        ;;
      *)
        threshold=$REGEX_CACHE_THRESHOLD
        budget_label="2.5ms"
        ;;
    esac

    headroom=$(( (threshold - ns_op) * 100 / threshold ))
    if [ "$ns_op" -gt "$threshold" ]; then
      status=":x: FAIL"
    elif [ "$headroom" -lt 20 ]; then
      status=":warning: WARN"
    else
      status=":white_check_mark: PASS"
    fi

    # Format ns_op for display
    if [ "$ns_op" -ge 1000000 ]; then
      display="$(echo "scale=1; $ns_op / 1000000" | bc)ms"
    elif [ "$ns_op" -ge 1000 ]; then
      display="$(echo "scale=1; $ns_op / 1000" | bc)µs"
    else
      display="${ns_op}ns"
    fi

    echo "| $name | $display | $budget_label | ${headroom}% | $status |"
  fi
done < "$BENCH_FILE"

echo ''
echo "_Budget: regex/cache < 2.5ms (0.5% of 500ms baseline), streaming < 20ms (4% of 500ms baseline)_"
