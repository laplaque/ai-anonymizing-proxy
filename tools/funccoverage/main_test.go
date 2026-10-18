package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mainEnv makes the test binary run main() instead of the tests, so the CLI
// tests below exercise the real entry point: its arguments, output and exit
// status. Under go test -cover the child inherits GOCOVERDIR from this
// process, and its coverage is merged into the package profile.
const mainEnv = "FUNCCOVERAGE_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(mainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// writeFile writes content to name under dir and returns its path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const src = `package lib

func Empty() {}

var hook = func(n int) int {
	return n * 2
}

func A() int { return 1 }; func B() int { return 2 }

func External() int
`

func TestRunAttributesBlocksByExtent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // file arguments are relative, as in delta-coverage.sh
	writeFile(t, dir, "lib.go", src)
	// go1.27-style blocks: each starts at the first statement. The hook
	// block is listed twice, as when two test binaries cover one package;
	// counts merge and its statement is counted once.
	profile := writeFile(t, dir, "cover.out", `mode: atomic
fixture/lib.go:6.2,6.14 1 0
fixture/lib.go:6.2,6.14 1 3
fixture/lib.go:9.16,9.24 1 1
fixture/lib.go:9.43,9.51 1 0
`)
	var out, warn bytes.Buffer
	if err := run([]string{profile, "lib.go"}, &out, &warn); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := "lib.go:3\tEmpty\t0\t0\n" +
		"lib.go:5\tfunc literal\t1\t1\n" +
		"lib.go:9\tA\t1\t1\n" +
		"lib.go:9\tB\t0\t1\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected warning: %q", warn.String())
	}
}

// TestRunRejectsUninstrumentedFile pins that a file built on this platform
// but absent from the profile is an error, not a file with nothing to cover.
func TestRunRejectsUninstrumentedFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // file arguments are relative, as in delta-coverage.sh
	writeFile(t, dir, "lib.go", src)
	writeFile(t, dir, "other.go", "package lib\n\nfunc Other() int { return 3 }\n")
	profile := writeFile(t, dir, "cover.out", "mode: set\nfixture/covered.go:3.1,3.5 1 1\n")
	var out, warn bytes.Buffer
	err := run([]string{profile, "lib.go", "other.go"}, &out, &warn)
	if err == nil || !strings.Contains(err.Error(), "no blocks in the coverage profile for lib.go, other.go") {
		t.Fatalf("run error = %v, want it to name both uninstrumented files", err)
	}
	// Every row is still reported before the error.
	if !strings.Contains(out.String(), "lib.go:9\tB\t0\t0\n") || !strings.Contains(out.String(), "other.go:3\tOther\t0\t0\n") {
		t.Errorf("output = %q", out.String())
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected warning: %q", warn.String())
	}
}

// TestRunWarnsForBuildExcludedFile pins that a file build constraints exclude
// on this platform is reported and skipped rather than failed: no test run
// here could have instrumented it.
func TestRunWarnsForBuildExcludedFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // file arguments are relative, as in delta-coverage.sh
	writeFile(t, dir, "excluded.go", "//go:build funccoverage_never\n\npackage lib\n\nfunc Excluded() int { return 1 }\n")
	profile := writeFile(t, dir, "cover.out", "mode: set\nfixture/covered.go:3.1,3.5 1 1\n")
	var out, warn bytes.Buffer
	if err := run([]string{profile, "excluded.go"}, &out, &warn); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(warn.String(), "excluded.go is excluded by build constraints") {
		t.Errorf("warning = %q", warn.String())
	}
	if out.String() != "excluded.go:5\tExcluded\t0\t0\n" {
		t.Errorf("output = %q", out.String())
	}
}

// TestRunFailsClosed pins that unusable input is an error, never an empty
// (and therefore passing) report.
func TestRunFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // file arguments are relative, as in delta-coverage.sh
	writeFile(t, dir, "lib.go", src)
	writeFile(t, dir, "broken.go", "package lib\n\nfunc {\n")
	good := writeFile(t, dir, "good.out", "mode: set\nfixture/lib.go:6.2,6.14 1 1\n")

	cases := map[string]struct {
		args    []string
		profile string // written to bad.out and prepended to args when set
		want    string
	}{
		"no arguments":         {args: nil, want: "usage"},
		"no files":             {args: []string{good}, want: "usage"},
		"missing profile":      {args: []string{filepath.Join(dir, "absent.out"), "lib.go"}, want: "absent.out"},
		"empty profile":        {profile: "", args: []string{"lib.go"}, want: "empty profile"},
		"no mode line":         {profile: "fixture/lib.go:6.2,6.14 1 1\n", args: []string{"lib.go"}, want: "missing mode line"},
		"no colon":             {profile: "mode: set\ngarbage\n", args: []string{"lib.go"}, want: "malformed block"},
		"blank line":           {profile: "mode: set\n\nfixture/lib.go:6.2,6.14 1 1\n", args: []string{"lib.go"}, want: "malformed block"},
		"wrong field count":    {profile: "mode: set\nf.go:1.1,2.2 1\n", args: []string{"lib.go"}, want: "malformed block"},
		"bad span":             {profile: "mode: set\nf.go:1.1 1 1\n", args: []string{"lib.go"}, want: "malformed span"},
		"bad start":            {profile: "mode: set\nf.go:x.1,2.2 1 1\n", args: []string{"lib.go"}, want: "bad position"},
		"bad end":              {profile: "mode: set\nf.go:1.1,2 1 1\n", args: []string{"lib.go"}, want: "bad position"},
		"bad statement count":  {profile: "mode: set\nf.go:1.1,2.2 x 1\n", args: []string{"lib.go"}, want: "bad statement count"},
		"bad hit count":        {profile: "mode: set\nf.go:1.1,2.2 1 x\n", args: []string{"lib.go"}, want: "bad hit count"},
		"overlong line":        {profile: "mode: set\n" + strings.Repeat("x", 70_000) + "\n", args: []string{"lib.go"}, want: "token too long"},
		"missing source file":  {args: []string{good, "absent.go"}, want: "absent.go"},
		"unparsable source":    {args: []string{good, "broken.go"}, want: "broken.go"},
		"second file unusable": {args: []string{good, "lib.go", "absent.go"}, want: "absent.go"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			args := tc.args
			if tc.profile != "" || name == "empty profile" {
				args = append([]string{writeFile(t, dir, "bad.out", tc.profile)}, args...)
			}
			var out, warn bytes.Buffer
			err := run(args, &out, &warn)
			if err == nil {
				t.Fatalf("run(%q) succeeded with output %q; want error containing %q", args, out.String(), tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// errWriter fails every write.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestRunReportsWriteErrors(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // file arguments are relative, as in delta-coverage.sh
	// The first row comes from a declared function in one file and from a
	// package-level literal in the other.
	writeFile(t, dir, "decl.go", "package lib\n\nfunc F() { _ = 1 }\n")
	writeFile(t, dir, "lit.go", "package lib\n\nvar f = func() { _ = 1 }\n")
	profile := writeFile(t, dir, "cover.out", "mode: set\nfixture/decl.go:3.12,3.17 1 1\nfixture/lit.go:3.18,3.23 1 1\n")
	for _, file := range []string{"decl.go", "lit.go"} {
		if err := run([]string{profile, file}, errWriter{}, &bytes.Buffer{}); !errors.Is(err, os.ErrClosed) {
			t.Errorf("%s: run error = %v, want the writer's error", file, err)
		}
	}
}

// TestMainCLI runs the compiled entry point as delta-coverage.sh does and
// checks its standard output, standard error and exit status.
func TestMainCLI(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "lib.go", src)
	writeFile(t, dir, "excluded.go", "//go:build funccoverage_never\n\npackage lib\n\nfunc Excluded() int { return 1 }\n")
	writeFile(t, dir, "other.go", "package lib\n\nfunc Other() int { return 3 }\n")
	writeFile(t, dir, "cover.out", "mode: atomic\nfixture/lib.go:6.2,6.14 1 3\nfixture/lib.go:9.16,9.24 1 1\nfixture/lib.go:9.43,9.51 1 0\n")
	rows := "lib.go:3\tEmpty\t0\t0\n" +
		"lib.go:5\tfunc literal\t1\t1\n" +
		"lib.go:9\tA\t1\t1\n" +
		"lib.go:9\tB\t0\t1\n"

	cases := []struct {
		name       string
		args       []string
		wantExit   int
		wantStdout string
		wantStderr string // substring; "" means stderr must be empty
	}{
		{"report", []string{"cover.out", "lib.go"}, 0, rows, ""},
		{"build-excluded file", []string{"cover.out", "lib.go", "excluded.go"}, 0,
			rows + "excluded.go:5\tExcluded\t0\t0\n", "funccoverage: warning: excluded.go is excluded by build constraints"},
		{"usage", []string{"cover.out"}, 1, "", "funccoverage: usage: funccoverage <coverage-profile> <file>"},
		{"unreadable profile", []string{"absent.out", "lib.go"}, 1, "", "funccoverage: open absent.out"},
		{"uninstrumented file", []string{"cover.out", "lib.go", "other.go"}, 1,
			rows + "other.go:3\tOther\t0\t0\n", "funccoverage: no blocks in the coverage profile for other.go, although built on"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			//nolint:gosec // G204: os.Args[0] is this test binary (the stdlib helper-process pattern); the arguments are the test table's constants.
			cmd := exec.CommandContext(t.Context(), os.Args[0], tc.args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), mainEnv+"=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			exit := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exit = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("run CLI: %v", err)
			}
			if exit != tc.wantExit {
				t.Errorf("exit status = %d, want %d (stderr %q)", exit, tc.wantExit, stderr.String())
			}
			if stdout.String() != tc.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tc.wantStdout)
			}
			if tc.wantStderr == "" && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}
