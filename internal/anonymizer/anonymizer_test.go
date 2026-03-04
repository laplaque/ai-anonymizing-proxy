package anonymizer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
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

// TestLowConfidenceCacheHitWithMetrics verifies that cache hit metrics are
// recorded when the metrics collector is present.
func TestLowConfidenceCacheHitWithMetrics(t *testing.T) {
	m := metrics.New()

	// First pass to discover the exact regex match.
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

	// Now test cache hit with metrics.
	a := New("http://localhost:11434", "test-model", true, 0.80, 1, m)
	a.cache.Set(matchedValue, "[PII_cached01]")

	a.AnonymizeText(input, "sess-metrics-hit")

	snap := m.Snapshot()
	totalHits := int64(0)
	for _, v := range snap.PIITokens.CacheHits {
		totalHits += v
	}
	if totalHits == 0 {
		t.Error("expected CacheHits > 0 after cache hit with metrics")
	}
}

// TestLowConfidenceCacheMissWithMetrics verifies that cache miss metrics are
// recorded when the metrics collector is present.
func TestLowConfidenceCacheMissWithMetrics(t *testing.T) {
	m := metrics.New()
	a := New("http://localhost:11434", "test-model", true, 0.80, 1, m)

	// Phone has confidence 0.65, below the 0.80 threshold — triggers cache miss.
	input := "555-867-5309 is my number"
	a.AnonymizeText(input, "sess-metrics-miss")

	snap := m.Snapshot()
	totalMisses := int64(0)
	for _, v := range snap.PIITokens.CacheMisses {
		totalMisses += v
	}
	if totalMisses == 0 {
		t.Error("expected CacheMisses > 0 after cache miss with metrics")
	}
	if snap.PIITokens.CacheFallbacks == 0 {
		t.Error("expected CacheFallbacks > 0 after cache miss with metrics")
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
		t.Fatalf("output is not valid JSON: %v", err)
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
func TestAnonymizeIPv6(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-ipv6-1"

	cases := []struct {
		name  string
		input string
	}{
		{"loopback", "connect to ::1"},
		{"ula prefix", "network fc00::/7 is private"},
		{"link-local", "interface fe80::/10 assigned"},
		{"full address", "server at 2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"compressed", "host 2001:db8::1 responded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := a.AnonymizeText(tc.input, sessionID)
			if result == tc.input {
				t.Errorf("IPv6 address not anonymized in %q", tc.input)
			}
		})
	}
}

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

// --- Coverage gap tests ---

// TestAnonymizeTextEmpty verifies the early return for empty input.
func TestAnonymizeTextEmpty(t *testing.T) {
	a := newTestAnonymizer()
	if got := a.AnonymizeText("", "s"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// TestInjectPIIInstructionEmptyInstruction covers the empty-instruction guard.
func TestInjectPIIInstructionEmptyInstruction(t *testing.T) {
	a := newTestAnonymizer()
	doc := map[string]any{"system": "original prompt"}
	a.injectPIIInstruction(doc, "")
	if doc["system"] != "original prompt" {
		t.Errorf("empty instruction modified doc: %v", doc["system"])
	}
}

// TestInjectPIIInstructionEmptySystemString covers the empty system string path.
func TestInjectPIIInstructionEmptySystemString(t *testing.T) {
	a := newTestAnonymizer()
	doc := map[string]any{
		"system":   "",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}
	a.injectPIIInstruction(doc, "injected")
	if doc["system"] != "injected" {
		t.Errorf("expected 'injected', got %v", doc["system"])
	}
}

// TestInjectPIIInstructionOpenAIEmptyContent covers the OpenAI empty system content path.
func TestInjectPIIInstructionOpenAIEmptyContent(t *testing.T) {
	a := newTestAnonymizer()
	doc := map[string]any{
		"messages": []any{
			map[string]any{"role": "system", "content": ""},
			map[string]any{"role": "user", "content": "hi"},
		},
	}
	a.injectPIIInstruction(doc, "injected")
	msgs, ok := doc["messages"].([]any)
	if !ok {
		t.Fatal("messages is not []any")
	}
	sysMsg, ok := msgs[0].(map[string]any)
	if !ok {
		t.Fatal("first message is not map[string]any")
	}
	if sysMsg["content"] != "injected" {
		t.Errorf("expected 'injected', got %v", sysMsg["content"])
	}
}

// TestInjectPIIInstructionOpenAINoSystemMessage covers prepending a system message
// when none exists in the messages array.
func TestInjectPIIInstructionOpenAINoSystemMessage(t *testing.T) {
	a := newTestAnonymizer()
	doc := map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": "hello"},
		},
	}
	a.injectPIIInstruction(doc, "injected")
	msgs, ok := doc["messages"].([]any)
	if !ok {
		t.Fatal("messages is not []any")
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	first, ok := msgs[0].(map[string]any)
	if !ok {
		t.Fatal("first message is not map[string]any")
	}
	if first["role"] != "system" || first["content"] != "injected" {
		t.Errorf("system message not prepended: %v", first)
	}
}

// TestWalkValuePrimitiveTypes covers the default case in walkValue for
// non-string/non-container JSON types (numbers, booleans, nil).
func TestWalkValuePrimitiveTypes(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"Email alice@example.com"}],"temperature":0.7,"stream":true,"max_tokens":100}`)
	out := a.AnonymizeJSON(body, "sess-walk-prim")

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	// Verify primitive values survived unchanged.
	if doc["temperature"] != 0.7 {
		t.Errorf("temperature changed: %v", doc["temperature"])
	}
	if doc["stream"] != true {
		t.Errorf("stream changed: %v", doc["stream"])
	}
	if doc["max_tokens"] != float64(100) {
		t.Errorf("max_tokens changed: %v", doc["max_tokens"])
	}
}

// TestNewWithCacheAndCapacityBboltS3FIFO covers the bbolt+S3FIFO cache path.
func TestNewWithCacheAndCapacityBboltS3FIFO(t *testing.T) {
	dir := t.TempDir()
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test-model",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		CachePath:           dir + "/test.db",
		CacheCapacity:       100,
	})
	defer a.Close() //nolint:errcheck

	// Verify the cache works through the S3FIFO layer.
	a.cache.Set("test@example.com", "[PII_EMAIL_test1234]")
	tok, ok := a.cache.Get("test@example.com")
	if !ok || tok != "[PII_EMAIL_test1234]" {
		t.Errorf("S3FIFO cache round-trip failed: ok=%v tok=%q", ok, tok)
	}
	a.cache.Delete("test@example.com")
	_, ok = a.cache.Get("test@example.com")
	if ok {
		t.Error("entry not deleted from S3FIFO cache")
	}
}

// TestNewWithCacheAndCapacityBboltBare covers the bare bbolt path (capacity=0).
func TestNewWithCacheAndCapacityBboltBare(t *testing.T) {
	dir := t.TempDir()
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test-model",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		CachePath:           dir + "/bare.db",
		CacheCapacity:       0,
	})
	defer a.Close() //nolint:errcheck

	a.cache.Set("val", "tok")
	tok, ok := a.cache.Get("val")
	if !ok || tok != "tok" {
		t.Errorf("bare bbolt cache round-trip failed: ok=%v tok=%q", ok, tok)
	}
}

// TestNewWithCacheAndCapacityInvalidPath covers the bbolt open error fallback.
func TestNewWithCacheAndCapacityInvalidPath(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "test-model",
		UseAI:               false,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
		CachePath:           "/nonexistent/dir/cache.db",
		CacheCapacity:       100,
	})
	// Should fall back to memory cache without panicking.
	a.cache.Set("val", "tok")
	tok, ok := a.cache.Get("val")
	if !ok || tok != "tok" {
		t.Errorf("memory fallback cache failed: ok=%v tok=%q", ok, tok)
	}
}

// TestDispatchOllamaAsyncSemaphoreFull covers the semaphore-full default branch
// by using a synchronous approach: we fill the semaphore, dispatch, then wait
// for the inflight map to clear (proving the goroutine ran and returned via
// the default path without acquiring the semaphore).
func TestDispatchOllamaAsyncSemaphoreFull(t *testing.T) {
	m := metrics.New()
	a := New("http://localhost:11434", "test-model", true, 0.80, 1, m)

	// Fill the semaphore so the goroutine cannot acquire it.
	a.ollamaSem <- struct{}{}

	a.dispatchOllamaAsync("test-value")

	// Wait for inflight to clear — this means the goroutine has completed.
	for range 10000 {
		runtime.Gosched()
		a.inflightMu.Lock()
		done := !a.inflight["test-value"]
		a.inflightMu.Unlock()
		if done {
			break
		}
	}

	// Now drain semaphore (it was never consumed by the goroutine).
	<-a.ollamaSem

	errs := m.OllamaErrors.Load()
	if errs == 0 {
		t.Error("expected OllamaErrors > 0 when semaphore is full")
	}
}

// TestDispatchOllamaAsyncInflightDedup covers the in-flight dedup guard.
func TestDispatchOllamaAsyncInflightDedup(t *testing.T) {
	m := metrics.New()
	a := New("http://localhost:11434", "test-model", true, 0.80, 1, m)

	// Mark the value as in-flight manually so dispatch is deduplicated.
	a.inflightMu.Lock()
	a.inflight["same-value"] = true
	a.inflightMu.Unlock()

	before := m.OllamaDispatches.Load()
	a.dispatchOllamaAsync("same-value")
	after := m.OllamaDispatches.Load()

	// Clean up.
	a.inflightMu.Lock()
	delete(a.inflight, "same-value")
	a.inflightMu.Unlock()

	if after != before {
		t.Errorf("expected dedup: dispatches went from %d to %d", before, after)
	}
}

// TestRecordMappingEmptySessionID covers the empty-sessionID guard.
func TestRecordMappingEmptySessionID(t *testing.T) {
	a := newTestAnonymizer()
	// Should be a no-op, not panic.
	a.recordMapping("", "[PII_EMAIL_test]", "test@example.com")
	a.sessionMu.RLock()
	if len(a.sessions) != 0 {
		t.Error("empty sessionID should not create session entry")
	}
	a.sessionMu.RUnlock()
}

// TestAnonymizeJSONInvalidJSON covers the non-JSON fallback in AnonymizeJSON.
func TestAnonymizeJSONInvalidJSON(t *testing.T) {
	a := newTestAnonymizer()
	body := []byte(`not json at all, email alice@example.com`)
	out := a.AnonymizeJSON(body, "sess-bad-json")
	if strings.Contains(string(out), "alice@example.com") {
		t.Errorf("PII not anonymized in plain-text fallback: %s", out)
	}
}

// TestDeanonymizeTextEmptyText covers the empty-text guard in DeanonymizeText.
func TestDeanonymizeTextEmptyText(t *testing.T) {
	a := newTestAnonymizer()
	if got := a.DeanonymizeText("", "some-session"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// TestQueryOllamaHTTPSuccess covers the happy path of queryOllamaHTTP.
func TestQueryOllamaHTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := `{"response":"[{\"original\":\"alice@example.com\",\"type\":\"email\",\"confidence\":0.95}]"}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp)) //nolint:errcheck
	}))
	defer srv.Close()

	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      srv.URL,
		OllamaModel:         "test",
		UseAI:               true,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
	})
	// Fix the URL — New appends "/api/generate" but httptest handles all paths.
	a.ollamaURL = srv.URL

	detections, err := a.queryOllamaHTTP("contact alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(detections) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(detections))
	}
	if detections[0].Original != "alice@example.com" {
		t.Errorf("unexpected original: %q", detections[0].Original)
	}
}

// TestQueryOllamaHTTPBadJSON covers the response parse error path.
func TestQueryOllamaHTTPBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`not json`)) //nolint:errcheck
	}))
	defer srv.Close()

	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      srv.URL,
		OllamaModel:         "test",
		UseAI:               true,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
	})
	a.ollamaURL = srv.URL

	_, err := a.queryOllamaHTTP("test")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// TestQueryOllamaHTTPNoArray covers the "no JSON array" error path.
func TestQueryOllamaHTTPNoArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := `{"response":"I found no PII in this text."}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp)) //nolint:errcheck
	}))
	defer srv.Close()

	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      srv.URL,
		OllamaModel:         "test",
		UseAI:               true,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
	})
	a.ollamaURL = srv.URL

	_, err := a.queryOllamaHTTP("test")
	if err == nil || !strings.Contains(err.Error(), "no JSON array") {
		t.Fatalf("expected 'no JSON array' error, got: %v", err)
	}
}

// TestQueryOllamaHTTPBadArrayJSON covers the detection parse error path.
func TestQueryOllamaHTTPBadArrayJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := `{"response":"[{bad json}]"}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp)) //nolint:errcheck
	}))
	defer srv.Close()

	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      srv.URL,
		OllamaModel:         "test",
		UseAI:               true,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
	})
	a.ollamaURL = srv.URL

	_, err := a.queryOllamaHTTP("test")
	if err == nil || !strings.Contains(err.Error(), "detection parse error") {
		t.Fatalf("expected 'detection parse error', got: %v", err)
	}
}

// TestQueryOllamaHTTPConnectionRefused covers the HTTP Do error path.
func TestQueryOllamaHTTPConnectionRefused(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{
		OllamaEndpoint:      "http://127.0.0.1:1",
		OllamaModel:         "test",
		UseAI:               true,
		AIThreshold:         0.8,
		OllamaMaxConcurrent: 1,
	})
	a.ollamaURL = "http://127.0.0.1:1"

	_, err := a.queryOllamaHTTP("test")
	if err == nil {
		t.Fatal("expected connection error")
	}
}
