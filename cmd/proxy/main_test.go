package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/config"
)

// captureStdout redirects os.Stdout to a pipe for the duration of fn,
// then returns everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("pipe write close: %v", closeErr)
	}
	os.Stdout = old

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

func TestPrintBanner_ContainsExpectedFields(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:      8080,
		ManagementPort: 8081,
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "qwen2.5:3b",
		UseAIDetection: true,
	}

	out := captureStdout(t, func() { printBanner(cfg) })

	for _, want := range []string{"8080", "8081", "localhost:11434", "qwen2.5:3b"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in banner output, got:\n%s", want, out)
		}
	}
}

func TestPrintBanner_UpstreamProxy_FromEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://corporate:8888")

	cfg := &config.Config{ProxyPort: 8080, ManagementPort: 8081}
	out := captureStdout(t, func() { printBanner(cfg) })

	if !strings.Contains(out, "http://corporate:8888") {
		t.Errorf("expected upstream proxy in banner, got:\n%s", out)
	}
}

func TestPrintBanner_NoProxy_ShowsDirect(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")

	cfg := &config.Config{ProxyPort: 8080, ManagementPort: 8081}
	out := captureStdout(t, func() { printBanner(cfg) })

	if !strings.Contains(out, "direct") {
		t.Errorf("expected 'direct' in banner when no proxy set, got:\n%s", out)
	}
}

// TestMain_Smoke verifies the package compiles and the binary entry point exists.
// The actual main() starts network listeners so it cannot be called in tests.
func TestMain_Smoke(t *testing.T) {
	// Verify printBanner doesn't panic with zero-value config
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("printBanner panicked: %v", r)
			}
		}()
		captureStdout(t, func() { printBanner(&config.Config{}) })
	}()

	// Self-referential sanity: package name is main
	if fmt.Sprintf("%T", main) != "func()" {
		t.Error("expected main to be func()")
	}
}
