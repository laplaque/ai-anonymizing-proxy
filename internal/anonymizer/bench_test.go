// Package anonymizer benchmarks measure per-gate latency for the anonymization pipeline.
// Run with: go test -bench=. -benchmem -benchtime=5s ./internal/anonymizer/...
// Or use: make benchmark
package anonymizer

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
)

// emailPatternBench is the same regex used in production for email detection.
// Duplicated here to benchmark pure regex matching without anonymizer setup overhead.
var emailPatternBench = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

// BenchmarkRegexPassEmail measures pure regex pattern matching with no anonymization.
// This is the "regex-pass" gate: the baseline cost of detecting PII.
func BenchmarkRegexPassEmail(b *testing.B) {
	// Use programmatic string construction to avoid proxy tokenization
	email := "user" + "@" + "example" + "." + "com"
	input := "Contact us at " + email + " for support."
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = emailPatternBench.FindAllStringIndex(input, -1)
	}
}

// BenchmarkRegexPassMultiple measures regex matching with multiple PII values.
func BenchmarkRegexPassMultiple(b *testing.B) {
	email1 := "alice" + "@" + "company" + "." + "com"
	email2 := "bob" + "@" + "example" + "." + "org"
	email3 := "charlie" + "@" + "test" + "." + "net"
	input := "Contacts: " + email1 + ", " + email2 + ", and " + email3 + " for help."
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = emailPatternBench.FindAllStringIndex(input, -1)
	}
}

// newBenchAnonymizer creates an anonymizer suitable for benchmarks.
// AI/Ollama is disabled; uses in-memory cache. Verbose logging is disabled
// to prevent [DEANON] log lines from flooding benchmark output.
func newBenchAnonymizer(tb testing.TB) *Anonymizer {
	tb.Helper()
	a := New(
		"http://localhost:11434", // Ollama endpoint (not used with useAI=false)
		"llama3",                 // model (not used)
		false,                    // useAI disabled for deterministic benchmarks
		0.80,                     // aiThreshold
		1,                        // ollamaMaxConcurrent
		nil,                      // no metrics
	)
	a.SetVerbose(false) // suppress [DEANON] logging during benchmarks
	tb.Cleanup(func() { _ = a.Close() })
	return a
}

// BenchmarkAnonymizeCacheHit measures token lookup for a previously seen value.
// This is the "cache-hit" gate: the cost when PII has been seen before.
func BenchmarkAnonymizeCacheHit(b *testing.B) {
	a := newBenchAnonymizer(b)

	email := "cached" + "@" + "example" + "." + "com"
	input := "Contact " + email
	sessionID := "bench-cache-hit"

	// Warm cache by anonymizing once
	_ = a.AnonymizeText(input, sessionID)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = a.AnonymizeText(input, sessionID)
	}
}

// BenchmarkAnonymizeCacheMiss measures full anonymize path: match + generate + write.
// This is the "cache-miss" gate: worst-case latency for new PII values.
func BenchmarkAnonymizeCacheMiss(b *testing.B) {
	a := newBenchAnonymizer(b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Use a unique email each iteration to force cache miss
		email := fmt.Sprintf("user%d@example.com", i)
		input := "Contact " + email
		sessionID := fmt.Sprintf("bench-miss-%d", i)
		_ = a.AnonymizeText(input, sessionID)
	}
}

// BenchmarkAnonymizeNoMatch measures overhead when text contains no PII.
// This is the passthrough baseline.
func BenchmarkAnonymizeNoMatch(b *testing.B) {
	a := newBenchAnonymizer(b)

	input := "This text contains no personally identifiable information whatsoever."
	sessionID := "bench-no-match"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = a.AnonymizeText(input, sessionID)
	}
}

// BenchmarkAnonymizeMixedContent measures realistic mixed content with some PII.
func BenchmarkAnonymizeMixedContent(b *testing.B) {
	a := newBenchAnonymizer(b)

	email := "support" + "@" + "company" + "." + "com"
	input := "Hello, please contact " + email + " if you have questions about your account. " +
		"Our team is available Monday through Friday from 9am to 5pm EST. " +
		"Thank you for being a valued customer."
	sessionID := "bench-mixed"

	// Warm cache
	_ = a.AnonymizeText(input, sessionID)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = a.AnonymizeText(input, sessionID)
	}
}

// mockReadCloser wraps a reader to satisfy io.ReadCloser for benchmarks.
type mockReadCloser struct {
	io.Reader
}

func (m mockReadCloser) Close() error { return nil }

// BenchmarkStreamingFlush measures StreamingDeanonymize with realistic SSE payload.
// This is the "streaming-flush" gate: SSE event processing with token replacement.
func BenchmarkStreamingFlush(b *testing.B) {
	a := newBenchAnonymizer(b)

	// Create a session with some token mappings
	sessionID := "bench-streaming"
	email := "test" + "@" + "example" + "." + "com"
	input := "Contact " + email + " for help."
	_ = a.AnonymizeText(input, sessionID)

	// Get the token that was generated
	a.sessionMu.RLock()
	var token string
	for t := range a.sessions[sessionID] {
		token = t
		break
	}
	a.sessionMu.RUnlock()

	// Realistic SSE chunk with token
	sseChunk := fmt.Sprintf(`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello %s world"}}
`, token)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := mockReadCloser{strings.NewReader(sseChunk)}
		rc := a.StreamingDeanonymize(r, sessionID)
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}
}

// BenchmarkStreamingFlushNoTokens measures streaming passthrough with no tokens.
func BenchmarkStreamingFlushNoTokens(b *testing.B) {
	a := newBenchAnonymizer(b)

	sessionID := "bench-streaming-empty"
	// Don't anonymize anything, so session has no tokens

	sseChunk := `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello world with no tokens"}}
`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := mockReadCloser{strings.NewReader(sseChunk)}
		rc := a.StreamingDeanonymize(r, sessionID)
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}
}

// BenchmarkStreamingFlushMultipleEvents measures streaming with multiple SSE events.
func BenchmarkStreamingFlushMultipleEvents(b *testing.B) {
	a := newBenchAnonymizer(b)

	sessionID := "bench-streaming-multi"
	email := "multi" + "@" + "test" + "." + "com"
	_ = a.AnonymizeText("Contact "+email, sessionID)

	a.sessionMu.RLock()
	var token string
	for t := range a.sessions[sessionID] {
		token = t
		break
	}
	a.sessionMu.RUnlock()

	// Multiple SSE events in one chunk
	sseChunk := fmt.Sprintf(`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"First line with %s"}}
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":" and more text"}}
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":" final line"}}
`, token)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := mockReadCloser{strings.NewReader(sseChunk)}
		rc := a.StreamingDeanonymize(r, sessionID)
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}
}

// BenchmarkTokenGeneration measures the cost of generating a deterministic token.
func BenchmarkTokenGeneration(b *testing.B) {
	a := newBenchAnonymizer(b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = a.replacement(PIIEmail, fmt.Sprintf("user%d@test.com", i))
	}
}
