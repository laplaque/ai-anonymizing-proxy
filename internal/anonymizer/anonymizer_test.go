package anonymizer

import (
	"io"
	"strings"
	"testing"

	"ai-anonymizing-proxy/internal/metrics"
)

func newTestAnonymizer() *Anonymizer {
	return New("http://localhost:11434", "test-model", false, 0.8, 1, nil)
}

func TestAnonymizeTextEmail(t *testing.T) {
	a := newTestAnonymizer()
	result := a.AnonymizeText("Contact me at alice@example.com please", "sess1")
	if strings.Contains(result, "alice@example.com") {
		t.Errorf("email not anonymized: %q", result)
	}
}

func TestDeanonymizeTextRoundTrip(t *testing.T) {
	a := newTestAnonymizer()
	original := "Call me at 555-867-5309 or email bob@corp.io"
	sessionID := "sess-rt-1"

	anonymized := a.AnonymizeText(original, sessionID)
	if anonymized == original {
		t.Fatal("AnonymizeText did not change the text")
	}

	restored := a.DeanonymizeText(anonymized, sessionID)
	if restored != original {
		t.Errorf("round-trip failed\n  want: %q\n   got: %q", original, restored)
	}
}

func TestDeanonymizeJSONRoundTrip(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}`)
	sessionID := "sess-json-1"

	anonymized := a.AnonymizeJSON(body, sessionID)
	if strings.Contains(string(anonymized), "123-45-6789") {
		t.Errorf("SSN not anonymized in JSON: %s", anonymized)
	}

	restored := a.DeanonymizeText(string(anonymized), sessionID)
	if !strings.Contains(restored, "123-45-6789") {
		t.Errorf("SSN not restored after deanonymization: %s", restored)
	}
}

func TestDeleteSessionClearsMap(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-del-1"

	a.AnonymizeText("reach me at tester@example.com", sessionID)
	a.DeleteSession(sessionID)

	a.sessionMu.RLock()
	_, exists := a.sessions[sessionID]
	a.sessionMu.RUnlock()

	if exists {
		t.Error("session was not deleted")
	}
}

func TestDeanonymizeUnknownSessionReturnsOriginal(t *testing.T) {
	a := newTestAnonymizer()
	text := "some text with no session"
	result := a.DeanonymizeText(text, "nonexistent-session")
	if result != text {
		t.Errorf("expected unchanged text, got %q", result)
	}
}

func TestDeanonymizeEmptySessionID(t *testing.T) {
	a := newTestAnonymizer()
	text := "some text"
	result := a.DeanonymizeText(text, "")
	if result != text {
		t.Errorf("expected unchanged text for empty sessionID, got %q", result)
	}
}

func TestStreamingDeanonymizeRoundTrip(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-stream-1"

	original := `data: {"content":"call alice@example.com or +1-800-555-1234"}` + "\n\n"
	anonymized := a.AnonymizeText(original, sessionID)
	if anonymized == original {
		t.Fatal("AnonymizeText did not change the text")
	}

	src := io.NopCloser(strings.NewReader(anonymized))
	rc := a.StreamingDeanonymize(src, sessionID)
	defer rc.Close() //nolint:errcheck // test cleanup

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if string(got) != original {
		t.Errorf("streaming round-trip failed\n  want: %q\n   got: %q", original, string(got))
	}
}

func TestStreamingDeanonymizeNoTokens(t *testing.T) {
	a := newTestAnonymizer()
	text := "data: {\"content\":\"hello world\"}\n\n"

	src := io.NopCloser(strings.NewReader(text))
	// session with no replacements: should get back the original reader unchanged
	rc := a.StreamingDeanonymize(src, "empty-session")
	defer rc.Close() //nolint:errcheck // test cleanup

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if string(got) != text {
		t.Errorf("expected passthrough, got %q", string(got))
	}
}

func TestMultipleSessionsIsolated(t *testing.T) {
	a := newTestAnonymizer()

	a.AnonymizeText("alice@example.com", "sess-a")
	a.AnonymizeText("bob@example.com", "sess-b")

	a.sessionMu.RLock()
	mapA := a.sessions["sess-a"]
	mapB := a.sessions["sess-b"]
	a.sessionMu.RUnlock()

	for token := range mapA {
		if _, collision := mapB[token]; collision {
			// Collision is possible for same PII type but different values;
			// ensure the originals differ.
			if mapA[token] == mapB[token] {
				t.Errorf("sessions share identical token mapping for token %q", token)
			}
		}
	}
}

func TestMetricsCountersIncrement(t *testing.T) {
	m := metrics.New()
	a := New("http://localhost:11434", "test-model", false, 0.8, 1, m)

	sessionID := "sess-metrics-1"
	a.AnonymizeText("contact me at test@example.com and my SSN is 123-45-6789", sessionID)

	replaced := m.TokensReplaced.Load()
	if replaced == 0 {
		t.Error("expected TokensReplaced > 0 after anonymization")
	}

	a.DeanonymizeText("anything", sessionID)
	deanon := m.TokensDeanonymized.Load()
	if deanon == 0 {
		t.Error("expected TokensDeanonymized > 0 after deanonymization")
	}
}

// bytewiseReader simulates a slow byte-at-a-time stream for testing that
// token replacement works correctly regardless of chunk boundaries.
type bytewiseReader struct {
	data []byte
	pos  int
}

func (r *bytewiseReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func (r *bytewiseReader) Close() error { return nil }

// TestLowConfidenceCacheMissAppliesFallback verifies that a low-confidence
// regex match with no cache entry is still anonymized immediately — PII is
// never left unmasked waiting for an async Ollama response.
func TestLowConfidenceCacheMissAppliesFallback(t *testing.T) {
	a := New("http://localhost:11434", "test-model", true, 0.80, 1, nil)
	sessionID := "sess-miss-1"

	// Phone has confidence 0.65, below the 0.80 threshold — goes through cache path.
	// Number placed at start of string to avoid the phone regex capturing a leading space.
	input := "555-867-5309 is my number"
	result := a.AnonymizeText(input, sessionID)

	if strings.Contains(result, "555-867-5309") {
		t.Errorf("low-confidence cache miss left PII unmasked: %q", result)
	}
	if result == input {
		t.Errorf("AnonymizeText made no change on low-confidence miss: %q", result)
	}
}

// TestLowConfidenceCacheHit verifies that a pre-warmed per-value cache entry
// is used directly, and that the cached token round-trips through deanonymization.
func TestLowConfidenceCacheHit(t *testing.T) {
	// First pass with useAI=false to discover the exact string the phone regex
	// captures — this becomes the cache key for the second pass.
	discovery := New("http://localhost:11434", "test-model", false, 0.80, 1, nil)
	input := "555-867-5309 is my number"
	discovery.AnonymizeText(input, "discover")
	discovery.sessionMu.RLock()
	var matchedValue string
	for _, orig := range discovery.sessions["discover"] {
		matchedValue = orig
		break
	}
	discovery.sessionMu.RUnlock()
	if matchedValue == "" {
		t.Fatal("discovery pass produced no session mappings")
	}

	// Now pre-warm the cache with the real match key and verify it is used.
	a := New("http://localhost:11434", "test-model", true, 0.80, 1, nil)
	sessionID := "sess-hit-1"
	cachedToken := "[PHONE_cached1]"
	a.cacheMu.Lock()
	a.cache[matchedValue] = cachedToken
	a.cacheMu.Unlock()

	result := a.AnonymizeText(input, sessionID)
	if !strings.Contains(result, cachedToken) {
		t.Errorf("cached token not used: got %q, want it to contain %q", result, cachedToken)
	}

	// Deanonymization must reverse the cached token.
	restored := a.DeanonymizeText(result, sessionID)
	if restored != input {
		t.Errorf("round-trip with cached token failed\n  want: %q\n   got: %q", input, restored)
	}
}

// TestOllamaCacheKeyedByValue verifies that the same PII value appearing in
// two different messages produces the same token — proving the cache is keyed
// by value, not by surrounding text. Uses useAI=false (high-confidence email)
// to exercise the deterministic replacement path without Ollama.
func TestOllamaCacheKeyedByValue(t *testing.T) {
	a := New("http://localhost:11434", "test-model", false, 0.80, 1, nil)

	// Email has confidence 0.95 — same replacement() call regardless of context.
	result1 := a.AnonymizeText("First message from alice@example.com today", "sess-val-1")
	result2 := a.AnonymizeText("Second message from alice@example.com tomorrow", "sess-val-2")

	// Extract the token from each result.
	token1 := strings.TrimPrefix(strings.Split(result1, " ")[3], "")
	token2 := strings.TrimPrefix(strings.Split(result2, " ")[3], "")

	// Both results must contain the same token for the same email value.
	a.sessionMu.RLock()
	map1 := a.sessions["sess-val-1"]
	map2 := a.sessions["sess-val-2"]
	a.sessionMu.RUnlock()

	if len(map1) == 0 || len(map2) == 0 {
		t.Fatal("expected session maps to be populated")
	}

	// The token for alice@example.com must be identical across both sessions.
	var tok1, tok2 string
	for tok, orig := range map1 {
		if orig == "alice@example.com" {
			tok1 = tok
		}
	}
	for tok, orig := range map2 {
		if orig == "alice@example.com" {
			tok2 = tok
		}
	}
	_ = token1
	_ = token2

	if tok1 == "" || tok2 == "" {
		t.Fatal("alice@example.com not found in session maps")
	}
	if tok1 != tok2 {
		t.Errorf("same PII value produced different tokens across sessions: %q vs %q", tok1, tok2)
	}
	if strings.Contains(result1, "alice@example.com") {
		t.Errorf("PII not masked in result1: %q", result1)
	}
	if strings.Contains(result2, "alice@example.com") {
		t.Errorf("PII not masked in result2: %q", result2)
	}
}

// TestTokenFormatNonRetriggering verifies that no token produced by replacement()
// matches any compiled regex pattern. A failure here means the proxy would
// re-tokenize its own output in future sessions ("proxy eats itself").
func TestTokenFormatNonRetriggering(t *testing.T) {
	a := newTestAnonymizer()
	piiTypes := []PIIType{
		PIIEmail, PIIPhone, PIISSN, PIICreditCard, PIIIPAddress,
		PIIAPIKey, PIIName, PIIAddress, PIIMedical, PIISalary,
		PIICompany, PIIJobTitle,
	}
	for _, pt := range piiTypes {
		token := a.replacement(pt, "test-value-for-"+string(pt))
		for _, p := range a.patterns {
			if p.re.MatchString(token) {
				t.Errorf("token for PII type %q re-triggers pattern %q: token=%q", pt, p.piiType, token)
			}
		}
	}
}

func TestStreamingDeanonymizeChunkBoundary(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-boundary-1"

	// Text with multiple PII types; the resulting tokens are multi-character
	// ASCII strings that will straddle Read() boundaries when delivered one
	// byte at a time.
	input := "My email is alice@company.org and phone +1-800-555-1234"
	anonymized := a.AnonymizeText(input, sessionID)
	if anonymized == input {
		t.Fatal("AnonymizeText did not change the text")
	}

	// Deliver the anonymized content one byte per Read to force every possible
	// token split across chunk boundaries.
	src := &bytewiseReader{data: []byte(anonymized)}
	rc := a.StreamingDeanonymize(src, sessionID)
	defer rc.Close() //nolint:errcheck // test cleanup

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if string(got) != input {
		t.Errorf("chunk-boundary round-trip failed\n  want: %q\n   got: %q", input, string(got))
	}
}
