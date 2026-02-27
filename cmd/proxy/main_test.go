package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/config"
)

func TestPrintBanner_ContainsExpectedFields(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:      8080,
		ManagementPort: 8081,
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "qwen2.5:3b",
		UseAIDetection: true,
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printBanner(cfg)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	for _, want := range []string{"8080", "8081", "localhost:11434", "qwen2.5:3b"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in banner output, got:\n%s", want, out)
		}
	}
}

func TestPrintBanner_UpstreamProxy_FromEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://corporate:8888")

	cfg := &config.Config{ProxyPort: 8080, ManagementPort: 8081}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printBanner(cfg)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "http://corporate:8888") {
		t.Errorf("expected upstream proxy in banner, got:\n%s", out)
	}
}

func TestPrintBanner_NoProxy_ShowsDirect(t *testing.T) {
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("HTTP_PROXY")

	cfg := &config.Config{ProxyPort: 8080, ManagementPort: 8081}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printBanner(cfg)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

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
		old := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w
		printBanner(&config.Config{})
		w.Close()
		os.Stdout = old
	}()

	// Self-referential sanity: package name is main
	if fmt.Sprintf("%T", main) != "func()" {
		t.Error("expected main to be func()")
	}
}
