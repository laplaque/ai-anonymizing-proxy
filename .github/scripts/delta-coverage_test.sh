#!/bin/bash
# delta-coverage_test.sh — regression tests for delta-coverage.sh.
#
# Each case builds a throwaway Go module in a git repository (a base commit,
# then a commit adding the fixture), produces a real coverage profile with
# `go test -coverprofile`, runs delta-coverage.sh against the base commit,
# and checks its exit status and output.
#
# Usage: delta-coverage_test.sh [path/to/delta-coverage.sh]
#
# Fixtures use the repository's Go toolchain. Set FIXTURE_GOTOOLCHAIN (e.g.
# go1.26.9) to profile them with a different compiler instead; block start
# positions differ between toolchains.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DELTA="$(cd "$(dirname "${1:-$SCRIPT_DIR/delta-coverage.sh}")" && pwd)/$(basename "${1:-delta-coverage.sh}")"
if [ -n "${FIXTURE_GOTOOLCHAIN:-}" ]; then
  fixture_go() { GOTOOLCHAIN="$FIXTURE_GOTOOLCHAIN" go "$@"; }
  GO_VERSION="$(cd / && fixture_go env GOVERSION)"
else
  fixture_go() { go "$@"; }
  GO_VERSION="$(cd "$SCRIPT_DIR" && go env GOVERSION)"
fi
GO_VERSION="${GO_VERSION#go}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "Fixture toolchain: go${GO_VERSION}"

passed=0
failed=0

# new_repo <name>: create a module with one base commit; print its path.
new_repo() {
  local dir="$work/$1"
  mkdir -p "$dir/lib"
  printf 'module fixture\n\ngo %s\n' "$GO_VERSION" > "$dir/go.mod"
  git -C "$dir" init -q
  git -C "$dir" add go.mod
  git -C "$dir" -c user.name=test -c user.email=test@example.invalid commit -q -m base
  echo "$dir"
}

# run_case <name> <want-exit> <dir> [<pattern> ...]: commit the fixture, run
# the gate at threshold 95, and require the exit status and every pattern
# (fixed strings; a leading "!" means the string must be absent).
run_case() {
  local name="$1" want_exit="$2" dir="$3"
  shift 3
  git -C "$dir" add -A
  git -C "$dir" -c user.name=test -c user.email=test@example.invalid commit -q -m fixture
  (cd "$dir" && fixture_go test -count=1 -covermode=atomic -coverprofile=coverage.out ./... >/dev/null)

  local out status=0
  out="$(cd "$dir" && bash "$DELTA" coverage.out 95.0 HEAD~1 2>&1)" || status=$?

  local ok=1 reason=""
  if [ "$status" -ne "$want_exit" ]; then
    ok=0
    reason="exit $status, want $want_exit"
  fi
  local p
  for p in "$@"; do
    if [ "${p:0:1}" = "!" ]; then
      if grep -qF -- "${p:1}" <<< "$out"; then
        ok=0
        reason="${reason:+$reason; }unexpected output: ${p:1}"
      fi
    elif ! grep -qF -- "$p" <<< "$out"; then
      ok=0
      reason="${reason:+$reason; }missing output: $p"
    fi
  done

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $name"
    passed=$((passed + 1))
  else
    echo "FAIL: $name ($reason)"
    sed 's/^/    | /' <<< "$out"
    failed=$((failed + 1))
  fi
}

# 1. An empty function followed by a fully covered package-level function
# literal: the literal's blocks belong to neither neighbor, so the empty
# function is skipped and nothing fails.
dir="$(new_repo empty-then-package-closure)"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

func Empty() {}

var hook = func(n int) int {
	if n > 0 {
		return n * 2
	}
	return -n
}

func Double(n int) int { return hook(n) }
EOF
cat > "$dir/lib/lib_test.go" <<'EOF'
package lib

import "testing"

func TestDouble(t *testing.T) {
	Empty()
	if Double(2) != 4 || Double(-3) != 3 {
		t.Fatal("unexpected result")
	}
}
EOF
run_case "empty function before covered package-level closure" 0 "$dir" \
  "SUCCESS" "Checked 2 functions" "(1 without statements skipped)" "!FAIL:"

# 2. Control: the same file with an uncovered package-level closure branch
# must fail, attributed to the literal rather than to Empty.
dir="$(new_repo empty-then-uncovered-package-closure)"
cp "$work/empty-then-package-closure/lib/lib.go" "$dir/lib/lib.go"
cat > "$dir/lib/lib_test.go" <<'EOF'
package lib

import "testing"

func TestDouble(t *testing.T) {
	if Double(2) != 4 {
		t.Fatal("unexpected result")
	}
}
EOF
run_case "uncovered package-level closure is rejected" 1 "$dir" \
  "FAIL: lib/lib.go:5: func literal 66.7% (2/3 statements)" "!Empty"

# 3. Control: an ordinary uncovered function after an empty function fails.
dir="$(new_repo uncovered-function)"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

func Empty() {}

func Covered(n int) int { return n + 1 }

func Uncovered(n int) int {
	m := n * 3
	return m
}
EOF
cat > "$dir/lib/lib_test.go" <<'EOF'
package lib

import "testing"

func TestCovered(t *testing.T) {
	if Covered(1) != 2 {
		t.Fatal("unexpected result")
	}
}
EOF
run_case "uncovered ordinary function is rejected" 1 "$dir" \
  "FAIL: lib/lib.go:7: Uncovered 0.0% (0/2 statements)" "!FAIL: lib/lib.go:3" "!FAIL: lib/lib.go:5"

# 4. Genuinely zero-statement functions (an empty method and an empty
# function) are skipped; the covered function is still checked.
dir="$(new_repo zero-statement-functions)"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

type T struct{}

func (T) Marker() {}

func Noop() {
}

func Covered(n int) int { return n + 1 }
EOF
cat > "$dir/lib/lib_test.go" <<'EOF'
package lib

import "testing"

func TestCovered(t *testing.T) {
	if Covered(1) != 2 {
		t.Fatal("unexpected result")
	}
}
EOF
run_case "zero-statement functions are skipped" 0 "$dir" \
  "SUCCESS" "Checked 1 functions" "(2 without statements skipped)"

# 5. Two functions on one line: only columns separate their blocks. The
# uncovered one must fail and the covered one must not.
dir="$(new_repo same-line-functions)"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

func A() int { return 1 }; func B() int { return 2 }
EOF
cat > "$dir/lib/lib_test.go" <<'EOF'
package lib

import "testing"

func TestA(t *testing.T) {
	if A() != 1 {
		t.Fatal("unexpected result")
	}
}
EOF
run_case "functions sharing a line are separated by column" 1 "$dir" \
  "FAIL: lib/lib.go:3: B 0.0% (0/1 statements)" "!: A "

# 6. Control: an uncovered closure inside a named function counts against
# that function.
dir="$(new_repo uncovered-nested-closure)"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

func Empty() {}

func Adder(n int) func() int {
	return func() int {
		return n + 1
	}
}
EOF
cat > "$dir/lib/lib_test.go" <<'EOF'
package lib

import "testing"

func TestAdder(t *testing.T) {
	if Adder(1) == nil {
		t.Fatal("nil closure")
	}
}
EOF
run_case "uncovered nested closure is rejected" 1 "$dir" \
  "FAIL: lib/lib.go:5: Adder 50.0% (1/2 statements)" "!FAIL: lib/lib.go:3"

echo ""
echo "${passed} passed, ${failed} failed"
[ "$failed" -eq 0 ]
