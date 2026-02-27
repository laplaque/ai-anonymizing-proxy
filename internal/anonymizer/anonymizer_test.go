package anonymizer

import (
	"encoding/json"
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
	cachedToken := "[PII_cached01]"
	a.cache.Set(matchedValue, cachedToken)

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
// TestAnonymizeJSONInjectsSystemInstructionAnthropicString verifies that when
// PII is detected in a request with an Anthropic-style string system field,
// the piiSystemInstruction is appended to the system prompt.
func TestAnonymizeJSONInjectsSystemInstructionAnthropicString(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`{"system":"You are a helpful assistant.","messages":[{"role":"user","content":"Email alice@example.com"}]}`)

	out := a.AnonymizeJSON(body, "sess-inject-1")

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err);
	}
	sys, _ := doc["system"].(string)
	if !strings.Contains(sys, "PRIVACY TOKENS") {
		t.Errorf("system prompt missing PII instruction; got: %q", sys)
	}
	if !strings.Contains(sys, "You are a helpful assistant.") {
		t.Errorf("original system prompt lost; got: %q", sys)
	}
}

// TestAnonymizeJSONInjectsSystemInstructionAnthropicBlockArray verifies injection
// when the Anthropic system field is a content-block array.
func TestAnonymizeJSONInjectsSystemInstructionAnthropicBlockArray(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`{"system":[{"type":"text","text":"Be concise."}],"messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}`)

	out := a.AnonymizeJSON(body, "sess-inject-2")

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	blocks, _ := doc["system"].([]any)
	if len(blocks) < 2 {
		t.Fatalf("expected at least 2 system blocks, got %d", len(blocks))
	}
	last, _ := blocks[len(blocks)-1].(map[string]any)
	text, _ := last["text"].(string)
	if !strings.Contains(text, "PRIVACY TOKENS") {
		t.Errorf("injected block missing PII instruction; got: %q", text)
	}
}

// TestAnonymizeJSONInjectsSystemInstructionOpenAI verifies injection for
// OpenAI-compatible requests where the system prompt is the first messages entry.
func TestAnonymizeJSONInjectsSystemInstructionOpenAI(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`{"model":"gpt-4","messages":[{"role":"system","content":"Be helpful."},{"role":"user","content":"Email bob@corp.io"}]}`)

	out := a.AnonymizeJSON(body, "sess-inject-3")

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	msgs, _ := doc["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatal("messages array empty")
	}
	first, _ := msgs[0].(map[string]any)
	content, _ := first["content"].(string)
	if first["role"] != "system" {
		t.Errorf("first message role is not system: %q", first["role"])
	}
	if !strings.Contains(content, "PRIVACY TOKENS") {
		t.Errorf("system message missing PII instruction; got: %q", content)
	}
	if !strings.Contains(content, "Be helpful.") {
		t.Errorf("original system content lost; got: %q", content)
	}
}

// TestAnonymizeJSONNoInjectionWhenNoPII verifies that the system prompt is
// NOT modified when no PII tokens are detected in the request.
func TestAnonymizeJSONNoInjectionWhenNoPII(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`{"system":"Be helpful.","messages":[{"role":"user","content":"Hello world"}]}`)

	out := a.AnonymizeJSON(body, "sess-inject-4")

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	sys, _ := doc["system"].(string)
	if strings.Contains(sys, "PRIVACY TOKENS") {
		t.Errorf("PII instruction injected when no PII was present; got: %q", sys)
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
