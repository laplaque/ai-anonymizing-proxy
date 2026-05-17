// Package envfile parses KEY=VALUE files and applies them to the process
// environment. Used by the binary's --env-file flag so platform packagers
// (Windows MSI service, macOS LaunchDaemon, Linux systemd as a fallback to
// EnvironmentFile=) can hand a single config-file path to the proxy.
package envfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Apply reads a KEY=VALUE file at path and sets each entry in the process
// environment via os.Setenv. Comments start with '#'. Blank lines are
// skipped. A surrounding pair of matching single or double quotes around
// the value is stripped.
//
// Caller-supplied paths are intentional: this is a CLI flag, and the
// service operator chooses the file.
func Apply(path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: path is an operator-supplied CLI flag value
	if err != nil {
		return fmt.Errorf("open env file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("env file %q line %d: missing '='", path, lineNo)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("env file %q line %d: empty key", path, lineNo)
		}
		value = strings.TrimSpace(value)
		value = unquote(value)
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("env file %q line %d: setenv %s: %w", path, lineNo, key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read env file %q: %w", path, err)
	}
	return nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
