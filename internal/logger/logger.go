// Package logger provides structured, level-gated logging for the proxy.
//
// Each entry is written as a single line with fixed-width columns:
//
//	2006-01-02 15:04:05.000 | MODULE       | ACTION               | LEVEL | message
//
// Levels (lowest to highest): debug, info, warn, error.
// Entries below the configured minimum level are silently dropped.
//
// Usage:
//
//	log := logger.New("PROXY", cfg.LogLevel)
//	log.Info("request_forward", "POST api.anthropic.com/v1/messages [ANON]")
//	log.Errorf("upstream_connect", "dial %s: %v", host, err)
package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// Level represents a log severity.
type Level int

// Log severity constants, ordered lowest to highest.
const (
	LevelDebug Level = iota // fine-grained diagnostic output
	LevelInfo               // normal operational messages
	LevelWarn               // unexpected but recoverable conditions
	LevelError              // failures requiring attention
)

// Logger writes structured log lines for a single module.
type Logger struct {
	module string
	level  Level
	out    *log.Logger
}

// New creates a Logger for the given module, gated at the given level string.
// Unrecognized level strings default to "info".
func New(module, levelStr string) *Logger {
	return &Logger{
		module: strings.ToUpper(module),
		level:  parseLevel(levelStr),
		// No prefix or flags — we supply the full line ourselves.
		out: log.New(os.Stderr, "", 0),
	}
}

// SetLevel changes the minimum log level at runtime.
func (l *Logger) SetLevel(levelStr string) {
	l.level = parseLevel(levelStr)
}

// Debug logs at DEBUG level.
func (l *Logger) Debug(action, msg string) { l.write(LevelDebug, "DEBUG", action, msg) }

// Info logs at INFO level.
func (l *Logger) Info(action, msg string) { l.write(LevelInfo, "INFO ", action, msg) }

// Warn logs at WARN level.
func (l *Logger) Warn(action, msg string) { l.write(LevelWarn, "WARN ", action, msg) }

// Error logs at ERROR level.
func (l *Logger) Error(action, msg string) { l.write(LevelError, "ERROR", action, msg) }

// Debugf logs a formatted message at DEBUG level.
func (l *Logger) Debugf(action, format string, args ...any) {
	l.Debug(action, fmt.Sprintf(format, args...))
}

// Infof logs a formatted message at INFO level.
func (l *Logger) Infof(action, format string, args ...any) {
	l.Info(action, fmt.Sprintf(format, args...))
}

// Warnf logs a formatted message at WARN level.
func (l *Logger) Warnf(action, format string, args ...any) {
	l.Warn(action, fmt.Sprintf(format, args...))
}

// Errorf logs a formatted message at ERROR level.
func (l *Logger) Errorf(action, format string, args ...any) {
	l.Error(action, fmt.Sprintf(format, args...))
}

// Fatal logs at ERROR level and then calls os.Exit(1).
func (l *Logger) Fatal(action, msg string) {
	l.Error(action, msg)
	os.Exit(1)
}

// Fatalf logs a formatted message at ERROR level and then calls os.Exit(1).
func (l *Logger) Fatalf(action, format string, args ...any) {
	l.Fatal(action, fmt.Sprintf(format, args...))
}

// write emits one log line if level >= l.level.
func (l *Logger) write(level Level, levelLabel, action, msg string) {
	if level < l.level {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	l.out.Printf("%s | %-12s | %-22s | %s | %s", ts, l.module, action, levelLabel, msg)
}

// parseLevel converts a string to a Level, defaulting to LevelInfo.
func parseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}
