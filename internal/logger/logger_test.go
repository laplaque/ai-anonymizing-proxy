package logger

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// newTestLogger returns a Logger that writes to a buffer instead of stderr.
func newTestLogger(module, level string, buf *bytes.Buffer) *Logger {
	l := New(module, level)
	l.out = log.New(buf, "", 0)
	return l
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		input string
		want  Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"warning", LevelWarn},
		{"WARN", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"unknown", LevelInfo}, // default
		{"", LevelInfo},        // default
	}
	for _, c := range cases {
		got := parseLevel(c.input)
		if got != c.want {
			t.Errorf("parseLevel(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestNew_ModuleUppercased(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("proxy", "info", &buf)
	l.Info("test", "msg")
	if !strings.Contains(buf.String(), "PROXY") {
		t.Errorf("expected module 'PROXY' in output, got: %s", buf.String())
	}
}

func TestLevelFiltering_DebugSuppressedAtInfo(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("TEST", "info", &buf)
	l.Debug("action", "this should not appear")
	if buf.Len() > 0 {
		t.Errorf("debug message should be suppressed at info level, got: %s", buf.String())
	}
}

func TestLevelFiltering_InfoPassesAtInfo(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("TEST", "info", &buf)
	l.Info("action", "hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("info message should appear, got: %s", buf.String())
	}
}

func TestLevelFiltering_WarnPassesAtInfo(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("TEST", "info", &buf)
	l.Warn("action", "warning msg")
	if !strings.Contains(buf.String(), "warning msg") {
		t.Errorf("warn should appear at info level, got: %s", buf.String())
	}
}

func TestLevelFiltering_ErrorPassesAtWarn(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("TEST", "warn", &buf)
	l.Error("action", "error msg")
	if !strings.Contains(buf.String(), "error msg") {
		t.Errorf("error should appear at warn level, got: %s", buf.String())
	}
}

func TestLevelFiltering_InfoSuppressedAtWarn(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("TEST", "warn", &buf)
	l.Info("action", "info msg")
	if buf.Len() > 0 {
		t.Errorf("info should be suppressed at warn level, got: %s", buf.String())
	}
}

func TestLevelFiltering_DebugPassesAtDebug(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("TEST", "debug", &buf)
	l.Debug("action", "debug msg")
	if !strings.Contains(buf.String(), "debug msg") {
		t.Errorf("debug should appear at debug level, got: %s", buf.String())
	}
}

func TestSetLevel_ChangesFilter(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("TEST", "error", &buf)

	l.Info("action", "should be hidden")
	if buf.Len() > 0 {
		t.Errorf("info suppressed at error level, got: %s", buf.String())
	}

	l.SetLevel("debug")
	l.Info("action", "should appear now")
	if !strings.Contains(buf.String(), "should appear now") {
		t.Errorf("info should appear after SetLevel(debug), got: %s", buf.String())
	}
}

func TestFormattedMethods(t *testing.T) {
	cases := []struct {
		name string
		fn   func(l *Logger, buf *bytes.Buffer)
		want string
	}{
		{"Debugf", func(l *Logger, buf *bytes.Buffer) { l.Debugf("a", "val=%d", 42) }, "val=42"},
		{"Infof", func(l *Logger, buf *bytes.Buffer) { l.Infof("a", "val=%d", 42) }, "val=42"},
		{"Warnf", func(l *Logger, buf *bytes.Buffer) { l.Warnf("a", "val=%d", 42) }, "val=42"},
		{"Errorf", func(l *Logger, buf *bytes.Buffer) { l.Errorf("a", "val=%d", 42) }, "val=42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := newTestLogger("TEST", "debug", &buf)
			c.fn(l, &buf)
			if !strings.Contains(buf.String(), c.want) {
				t.Errorf("%s: expected %q in output, got: %s", c.name, c.want, buf.String())
			}
		})
	}
}

func TestOutputFormat_ContainsExpectedFields(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger("MYMOD", "debug", &buf)
	l.Info("my_action", "the message")

	out := buf.String()
	for _, expected := range []string{"MYMOD", "my_action", "the message", "INFO"} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected %q in log output, got: %s", expected, out)
		}
	}
}
