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

# 7. Control: a changed file built on this platform but left out of the
# coverage run (here under a dot-directory, which ./... skips) must fail
# rather than pass as a file with nothing to cover.
dir="$(new_repo uninstrumented-file)"
mkdir -p "$dir/.hidden"
cat > "$dir/.hidden/tool.go" <<'EOF'
package hidden

func Tool(n int) int { return n + 1 }
EOF
cp "$work/uncovered-function/lib/lib_test.go" "$dir/lib/lib_test.go"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

func Covered(n int) int { return n + 1 }
EOF
run_case "uninstrumented changed file is rejected" 1 "$dir" \
  "funccoverage: no blocks in the coverage profile for .hidden/tool.go" "ERROR: funccoverage failed" "!SUCCESS"

# 8. A changed file that build constraints exclude on this platform is
# reported and skipped: no run here could have instrumented it.
dir="$(new_repo build-excluded-file)"
cp "$work/uncovered-function/lib/lib_test.go" "$dir/lib/lib_test.go"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

func Covered(n int) int { return n + 1 }
EOF
cat > "$dir/lib/excluded.go" <<'EOF'
//go:build funccoverage_never

package lib

func Excluded(n int) int { return n * 2 }
EOF
run_case "build-excluded changed file is skipped with a warning" 0 "$dir" \
  "funccoverage: warning: lib/excluded.go is excluded by build constraints" "Checked 1 functions" "SUCCESS"

# 9. A changed file with only type declarations has no executable code, so
# the compiler emits no coverage blocks for it; it must not fail the gate.
dir="$(new_repo types-only-file)"
cp "$work/uncovered-function/lib/lib_test.go" "$dir/lib/lib_test.go"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

func Covered(n int) int { return n + 1 }
EOF
cat > "$dir/lib/types.go" <<'EOF'
package lib

type T struct {
	Value int
}

type Doer interface {
	Do(n int) int
}
EOF
run_case "types-only changed file is accepted" 0 "$dir" \
  "Checked 1 functions" "SUCCESS" "!no blocks" "!FAIL"

# 10. Likewise a file with only constants and variables without function
# literals.
dir="$(new_repo constants-only-file)"
cp "$work/uncovered-function/lib/lib_test.go" "$dir/lib/lib_test.go"
cp "$work/types-only-file/lib/lib.go" "$dir/lib/lib.go"
cat > "$dir/lib/consts.go" <<'EOF'
package lib

const Default = 1

const (
	Low  = iota
	High
)

var Names = []string{"a", "b"}
EOF
run_case "constants-only changed file is accepted" 0 "$dir" \
  "Checked 1 functions" "SUCCESS" "!no blocks" "!FAIL"

# 11. Mixed declarations and executable code: the types and constants add
# nothing, and the file's function is checked as usual.
dir="$(new_repo mixed-declarations-covered)"
cp "$work/uncovered-function/lib/lib_test.go" "$dir/lib/lib_test.go"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

type T struct{ Value int }

const Default = 1

func Covered(n int) int { return n + Default }
EOF
run_case "mixed declarations with covered code pass" 0 "$dir" \
  "Checked 1 functions" "SUCCESS"

# 12. Control: the same mixed file with an uncovered function still fails.
dir="$(new_repo mixed-declarations-uncovered)"
cp "$work/uncovered-function/lib/lib_test.go" "$dir/lib/lib_test.go"
cat > "$dir/lib/lib.go" <<'EOF'
package lib

type T struct{ Value int }

const Default = 1

func Covered(n int) int { return n + 1 }

func Uncovered(n int) int {
	m := n * Default
	return m
}
EOF
run_case "mixed declarations with uncovered code fail" 1 "$dir" \
  "FAIL: lib/lib.go:9: Uncovered 0.0% (0/2 statements)"

# 13. Control: an executable file missing from the profile still fails,
# and a types-only file beside it in the same uninstrumented directory is
# not reported in its place.
dir="$(new_repo executable-missing-with-types)"
mkdir -p "$dir/.hidden"
cat > "$dir/.hidden/types.go" <<'EOF'
package hidden

type T struct{ Value int }
EOF
cat > "$dir/.hidden/tool.go" <<'EOF'
package hidden

func Tool(n int) int { return n + 1 }
EOF
cp "$work/uncovered-function/lib/lib_test.go" "$dir/lib/lib_test.go"
cp "$work/types-only-file/lib/lib.go" "$dir/lib/lib.go"
run_case "executable file missing from the profile fails beside a types-only file" 1 "$dir" \
  "funccoverage: no blocks in the coverage profile for .hidden/tool.go, although" "!types.go, although" "ERROR: funccoverage failed" "!SUCCESS"

echo ""
echo "${passed} passed, ${failed} failed"
[ "$failed" -eq 0 ]
