package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestRunWarnsForUninstrumentedFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // file arguments are relative, as in delta-coverage.sh
	writeFile(t, dir, "lib.go", src)
	profile := writeFile(t, dir, "cover.out", "mode: set\nfixture/other.go:3.1,3.5 1 1\n")
	var out, warn bytes.Buffer
	if err := run([]string{profile, "lib.go"}, &out, &warn); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(warn.String(), "lib.go has no blocks in the coverage profile") {
		t.Errorf("warning = %q", warn.String())
	}
	if !strings.Contains(out.String(), "lib.go:9\tB\t0\t0\n") {
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
	profile := writeFile(t, dir, "cover.out", "mode: set\nfixture/lib.go:6.2,6.14 1 1\n")
	// The first row comes from a declared function in one file and from a
	// package-level literal in the other.
	writeFile(t, dir, "decl.go", "package lib\n\nfunc F() {}\n")
	writeFile(t, dir, "lit.go", "package lib\n\nvar f = func() {}\n")
	for _, file := range []string{"decl.go", "lit.go"} {
		if err := run([]string{profile, file}, errWriter{}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: run succeeded writing to a failing writer", file)
		}
	}
}
