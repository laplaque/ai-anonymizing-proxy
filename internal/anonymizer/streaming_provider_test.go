package anonymizer

import (
	"io"
	"strings"
	"testing"
)

// readStreamResultForDomain is the shared helper used by all provider test files.
// It wires a pre-populated session into a fresh Anonymizer and runs
// StreamingDeanonymize against the given domain, returning the full output.
func readStreamResultForDomain(t *testing.T, sseInput string, tokenMap map[string]string, domain string) string {
	t.Helper()
	a := newTestAnonymizer()
	a.SetVerbose(false)
	sessionID := "test-session"
	a.sessionMu.Lock()
	a.sessions[sessionID] = tokenMap
	a.sessionMu.Unlock()
	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID, domain)
	defer rc.Close() //nolint:errcheck
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	return string(got)
}

// readStreamResultVerbose is like readStreamResultForDomain but runs with
// verbose logging enabled so the log.Printf branches are exercised.
func readStreamResultVerbose(t *testing.T, sseInput string, tokenMap map[string]string, domain string) string {
	t.Helper()
	a := newTestAnonymizer()
	a.SetVerbose(true)
	sessionID := "verbose-session"
	a.sessionMu.Lock()
	a.sessions[sessionID] = tokenMap
	a.sessionMu.Unlock()
	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID, domain)
	defer rc.Close() //nolint:errcheck
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	return string(got)
}

// TestProviderForDomain verifies that every registered domain maps to the
// expected provider and that unknown domains fall back to ProviderPassthrough.
func TestProviderForDomain(t *testing.T) {
	cases := []struct {
		domain   string
		want     Provider
	}{
		{"api.anthropic.com", ProviderAnthropic},
		{"api.openai.com", ProviderOpenAI},
		{"api.mistral.ai", ProviderOpenAI},
		{"api.together.xyz", ProviderOpenAI},
		{"api.perplexity.ai", ProviderOpenAI},
		{"api.huggingface.co", ProviderOpenAI},
		{"generativelanguage.googleapis.com", ProviderGemini},
		{"api.cohere.ai", ProviderCohere},
		{"api.replicate.com", ProviderReplicate},
		// Unknown domains must fall back to passthrough.
		{"unknown.example.com", ProviderPassthrough},
		{"", ProviderPassthrough},
		{"localhost:8080", ProviderPassthrough},
	}

	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			got := ProviderForDomain(tc.domain)
			if got != tc.want {
				t.Errorf("ProviderForDomain(%q) = %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

// TestNewStreamingDeanonymizer verifies that the factory returns a non-nil
// implementation for every named Provider value.
func TestNewStreamingDeanonymizer(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close() //nolint:errcheck
	defer pw.Close() //nolint:errcheck

	opts := streamDeanonymizerOpts{
		pw:         pw,
		replacer:   strings.NewReplacer(),
		sessionID:  "factory-test",
		verbose:    false,
		tokenCount: 0,
	}

	providers := []Provider{
		ProviderAnthropic,
		ProviderOpenAI,
		ProviderGemini,
		ProviderCohere,
		ProviderReplicate,
		ProviderPassthrough,
		Provider("unknown-provider"), // must also return non-nil (passthrough)
	}

	for _, p := range providers {
		t.Run(string(p), func(t *testing.T) {
			d := NewStreamingDeanonymizer(p, opts)
			if d == nil {
				t.Errorf("NewStreamingDeanonymizer(%q) returned nil", p)
			}
		})
	}
}
