// Command funccoverage reports per-function statement coverage for selected
// source files, for .github/scripts/delta-coverage.sh. It lives under tools/
// rather than next to the script so that ./... — and with it lint, gosec and
// the coverage profile the delta gate reads — includes it.
//
// Usage: funccoverage <coverage-profile> <file>...
//
// Each file is a path relative to the current directory (the repository
// root); a profile block belongs to that file when the profile's file name
// equals the path or ends with "/" followed by it. For every function
// declaration with a body, and every function literal outside one, it
// prints one tab-separated line:
//
//	<file>:<line>	<name>	<covered statements>	<total statements>
//
// A block counts toward a function when it lies entirely within the
// function's parsed extent, compared by line and column — the rule
// `go tool cover -func` uses — and a function whose extent holds no block
// reports 0 total statements. Function literals outside any declared
// function (in package-level var initializers) get their own row, named
// "func literal", so their statements are checked rather than dropped or
// attributed to a neighboring declaration.
//
// A file with no blocks in the profile was not instrumented by the test run.
// If build constraints exclude it on this platform (a _windows.go file on a
// Linux runner, say), funccoverage lists its functions with 0 total
// statements and prints a warning naming the file to stderr: nothing here
// could have covered it. Otherwise its package was left out of the coverage
// run, which is an error: an uninstrumented file must not pass as one with
// nothing to cover.
//
// It exits non-zero if the profile or any file cannot be read or parsed, or
// if a file built on this platform has no blocks in the profile.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// pos is a line/column source position.
type pos struct{ line, col int }

func (p pos) before(q pos) bool {
	return p.line < q.line || (p.line == q.line && p.col < q.col)
}

// block is one coverage profile block.
type block struct {
	file       string
	start, end pos
	numStmt    int
	count      int64
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "funccoverage:", err)
		os.Exit(1)
	}
}

func run(args []string, w, warn io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: funccoverage <coverage-profile> <file> [<file> ...]")
	}
	blocks, err := readProfile(args[0])
	if err != nil {
		return err
	}
	if os.Getenv("FUNCCOVERAGE_DUMP") == "1" {
		dumpBlocks(warn, blocks)
	}
	var uninstrumented []string
	for _, file := range args[1:] {
		fileBlocks := blocksFor(blocks, file)
		if len(fileBlocks) == 0 {
			built, err := build.Default.MatchFile(filepath.Dir(file), filepath.Base(file))
			if err != nil {
				return err
			}
			if built {
				uninstrumented = append(uninstrumented, file)
			} else {
				_, _ = fmt.Fprintf(warn, "funccoverage: warning: %s is excluded by build constraints on %s/%s; not checked\n",
					file, build.Default.GOOS, build.Default.GOARCH)
			}
		}
		if err := reportFile(w, file, fileBlocks); err != nil {
			return err
		}
	}
	if len(uninstrumented) > 0 {
		return fmt.Errorf("no blocks in the coverage profile for %s, although built on %s/%s: include their packages in the coverage run",
			strings.Join(uninstrumented, ", "), build.Default.GOOS, build.Default.GOARCH)
	}
	return nil
}

// readProfile parses a Go coverage profile ("mode: ..." followed by
// "name:sl.sc,el.ec numStmt count" lines). Repeated blocks, which appear when
// several test binaries cover the same package, are merged by summing counts.
func readProfile(path string) ([]block, error) {
	f, err := os.Open(path) //nolint:gosec // G703: the profile path is this CLI's own argument; reading it is the tool's purpose.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	index := map[block]int{} // key has count zeroed
	var blocks []block
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		text := sc.Text()
		if lineNo == 1 {
			if !strings.HasPrefix(text, "mode: ") {
				return nil, fmt.Errorf("%s: missing mode line", path)
			}
			continue
		}
		b, err := parseBlock(text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		key := b
		key.count = 0
		if i, ok := index[key]; ok {
			blocks[i].count += b.count
			continue
		}
		index[key] = len(blocks)
		blocks = append(blocks, b)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if lineNo == 0 {
		return nil, fmt.Errorf("%s: empty profile", path)
	}
	return blocks, nil
}

// parseBlock parses "name:sl.sc,el.ec numStmt count".
func parseBlock(text string) (block, error) {
	var b block
	colon := strings.LastIndexByte(text, ':')
	if colon < 0 {
		return b, fmt.Errorf("malformed block %q", text)
	}
	b.file = text[:colon]
	fields := strings.Fields(text[colon+1:])
	if len(fields) != 3 {
		return b, fmt.Errorf("malformed block %q", text)
	}
	span := strings.Split(fields[0], ",")
	if len(span) != 2 {
		return b, fmt.Errorf("malformed span in %q", text)
	}
	var err error
	if b.start, err = parsePos(span[0]); err != nil {
		return b, fmt.Errorf("%w in %q", err, text)
	}
	if b.end, err = parsePos(span[1]); err != nil {
		return b, fmt.Errorf("%w in %q", err, text)
	}
	if b.numStmt, err = strconv.Atoi(fields[1]); err != nil {
		return b, fmt.Errorf("bad statement count in %q", text)
	}
	if b.count, err = strconv.ParseInt(fields[2], 10, 64); err != nil {
		return b, fmt.Errorf("bad hit count in %q", text)
	}
	return b, nil
}

func parsePos(s string) (pos, error) {
	line, col, ok := strings.Cut(s, ".")
	if !ok {
		return pos{}, fmt.Errorf("bad position %q", s)
	}
	l, err1 := strconv.Atoi(line)
	c, err2 := strconv.Atoi(col)
	if err1 != nil || err2 != nil {
		return pos{}, fmt.Errorf("bad position %q", s)
	}
	return pos{l, c}, nil
}

// blocksFor returns the blocks whose profile file name is file or ends with
// "/"+file.
func blocksFor(blocks []block, file string) []block {
	var out []block
	for _, b := range blocks {
		if b.file == file || strings.HasSuffix(b.file, "/"+file) {
			out = append(out, b)
		}
	}
	return out
}

// reportFile parses file and writes one line per function declaration with
// a body and per function literal outside any declaration, counting the
// blocks that lie within each extent.
func reportFile(w io.Writer, file string, blocks []block) error {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	for _, decl := range parsed.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Body == nil {
				continue // implemented elsewhere (assembly, linkname): no statements
			}
			if err := reportExtent(w, fset, file, fn.Name.Name, fn, blocks); err != nil {
				return err
			}
			continue
		}
		// Outermost function literals in package-level declarations; literals
		// nested inside them are part of their extent.
		var lits []*ast.FuncLit
		ast.Inspect(decl, func(n ast.Node) bool {
			lit, ok := n.(*ast.FuncLit)
			if ok {
				lits = append(lits, lit)
			}
			return !ok
		})
		for _, lit := range lits {
			if err := reportExtent(w, fset, file, "func literal", lit, blocks); err != nil {
				return err
			}
		}
	}
	return nil
}

// reportExtent writes the row for one function extent.
func reportExtent(w io.Writer, fset *token.FileSet, file, name string, n ast.Node, blocks []block) error {
	startPos, endPos := fset.Position(n.Pos()), fset.Position(n.End())
	start, end := pos{startPos.Line, startPos.Column}, pos{endPos.Line, endPos.Column}
	var covered, total int
	for _, b := range blocks {
		if b.start.before(start) || end.before(b.end) {
			continue
		}
		total += b.numStmt
		if b.count > 0 {
			covered += b.numStmt
		}
	}
	_, err := fmt.Fprintf(w, "%s:%d\t%s\t%d\t%d\n", file, start.line, name, covered, total)
	return err
}

// dumpBlocks is DELIBERATELY UNTESTED: planted to show that the delta gate
// fails on an uncovered helper function. Not for merging.
func dumpBlocks(w io.Writer, blocks []block) {
	for _, b := range blocks {
		_, _ = fmt.Fprintf(w, "%s %d.%d-%d.%d %d %d\n", b.file, b.start.line, b.start.col, b.end.line, b.end.col, b.numStmt, b.count)
	}
}
