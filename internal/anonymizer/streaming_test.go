package anonymizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// --- Unit tests for extracted helpers ---

func TestSafeCutPoint(t *testing.T) {
	cases := []struct {
		name        string
		accumulated string
		want        int
	}{
		{"short text held", "hello", 0},
		{"exactly tokenSuffixLen held", strings.Repeat("x", tokenSuffixLen), 0},
		{"long text without bracket", strings.Repeat("a", 50), 50 - tokenSuffixLen},
		{"open bracket in suffix", strings.Repeat("a", 30) + "[PII_EMAIL", 30},
		{"closed bracket in suffix", strings.Repeat("a", 30) + "[PII_EMAIL_abc12345]rest", 30 + len("[PII_EMAIL_abc12345]rest") - tokenSuffixLen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := safeCutPoint(tc.accumulated)
			if got != tc.want {
				t.Errorf("safeCutPoint(%q) = %d, want %d", tc.accumulated, got, tc.want)
			}
		})
	}
}

// --- Issue #34 gap tests ---

// makeSSETextDelta builds an SSE line for a content_block_delta text_delta event.
func makeSSETextDelta(text string) string {
	env := sseEnvelope{
		Type:  "content_block_delta",
		Index: 0,
		Delta: &sseDelta{Type: "text_delta", Text: text},
	}
	b, _ := json.Marshal(env)
	return "data: " + string(b) + "\n"
}

// makeSSEThinkingDelta builds an SSE line for a thinking_delta event.
func makeSSEThinkingDelta(text string) string {
	env := sseEnvelope{
		Type:  "content_block_delta",
		Index: 0,
		Delta: &sseDelta{Type: "thinking_delta", Text: text},
	}
	b, _ := json.Marshal(env)
	return "data: " + string(b) + "\n"
}

// readStreamResult is a helper that sets up an anonymizer with a known token
// mapping, runs StreamingDeanonymize on the given SSE input, and returns the
// full output.
func readStreamResult(t *testing.T, sseInput string, tokenMap map[string]string) string {
	t.Helper()
	a := newTestAnonymizer()
	a.SetVerbose(false)
	sessionID := "test-session"

	// Inject the token map directly.
	a.sessionMu.Lock()
	a.sessions[sessionID] = tokenMap
	a.sessionMu.Unlock()

	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID)
	defer rc.Close() //nolint:errcheck

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	return string(got)
}

// TestStreamingDeanonymizeTokenSplitAcrossEvents verifies that a token split
// at every possible byte position across two text_delta events is correctly
// reassembled and replaced.
func TestStreamingDeanonymizeTokenSplitAcrossEvents(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	for splitPos := 1; splitPos < len(token); splitPos++ {
		t.Run(fmt.Sprintf("split_at_%d", splitPos), func(t *testing.T) {
			part1 := token[:splitPos]
			part2 := token[splitPos:]

			// Pad with enough leading text so the accumulator flushes.
			prefix := strings.Repeat("x", tokenSuffixLen+10)
			sseInput := makeSSETextDelta(prefix+part1) + makeSSETextDelta(part2+" world") + "\n"

			got := readStreamResult(t, sseInput, tokenMap)
			if !strings.Contains(got, original) {
				t.Errorf("split at %d: token not replaced in output:\n%s", splitPos, got)
			}
			if strings.Contains(got, token) {
				t.Errorf("split at %d: unreplaced token found in output:\n%s", splitPos, got)
			}
		})
	}
}

// TestStreamingDeanonymizeSuffixGuardLongestToken verifies that the longest
// possible token (PIICreditCard at 25 chars) is held in the accumulator
// rather than prematurely flushed when split across events.
func TestStreamingDeanonymizeSuffixGuardLongestToken(t *testing.T) {
	// Longest token: [PII_CREDITCARD_XXXXXXXX] = 25 chars
	token := "[PII_CREDITCARD_a1b2c3d4]"
	original := "4111-1111-1111-1111"
	tokenMap := map[string]string{token: original}

	if len(token) > tokenSuffixLen {
		t.Fatalf("token len %d exceeds tokenSuffixLen %d — guard is too small", len(token), tokenSuffixLen)
	}

	// Split the token at the midpoint across two events. The prefix ensures
	// the first flush only emits leading text, and the second event delivers
	// the rest of the token. Without trailing text after the token, the
	// complete token (25 chars < 26) stays in the accumulator and gets
	// flushed correctly at EOF.
	mid := len(token) / 2
	prefix := strings.Repeat("y", tokenSuffixLen+5)
	sseInput := makeSSETextDelta(prefix+token[:mid]) +
		makeSSETextDelta(token[mid:]) + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("longest token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("unreplaced token in output:\n%s", got)
	}
}

// TestStreamingDeanonymizeEOFWithPendingAccumulator verifies that text held
// in the accumulator at EOF is flushed via a synthetic text_delta event.
func TestStreamingDeanonymizeEOFWithPendingAccumulator(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	// Single short event — text stays in accumulator, then EOF forces flush.
	sseInput := makeSSETextDelta("Hello " + token)

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("EOF flush did not replace token:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("unreplaced token after EOF flush:\n%s", got)
	}
}

// TestStreamingDeanonymizeNonTextDeltaFlushesAccumulator verifies that when a
// non-text-delta event arrives while the accumulator has content, the
// accumulated text is flushed via a synthetic text_delta before the event.
func TestStreamingDeanonymizeNonTextDeltaFlushesAccumulator(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	// text_delta with token, then message_stop forces flush.
	sseInput := makeSSETextDelta("prefix "+token) +
		"data: {\"type\":\"message_stop\"}\n\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("non-text-delta did not trigger flush:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("unreplaced token after non-text-delta flush:\n%s", got)
	}
	if !strings.Contains(got, "message_stop") {
		t.Errorf("message_stop event missing from output:\n%s", got)
	}
}

// TestStreamingDeanonymizeDoneTerminator verifies that "data: [DONE]" passes
// through unchanged.
func TestStreamingDeanonymizeDoneTerminator(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("a", tokenSuffixLen+5)
	sseInput := makeSSETextDelta(prefix+token) +
		"data: [DONE]\n\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, "data: [DONE]") {
		t.Errorf("[DONE] terminator not passed through:\n%s", got)
	}
	if !strings.Contains(got, original) {
		t.Errorf("token not replaced before [DONE]:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("unreplaced token in output:\n%s", got)
	}
}

// TestStreamingDeanonymizeThinkingDelta verifies that tokens inside
// thinking_delta events are also replaced.
func TestStreamingDeanonymizeThinkingDelta(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	// Enough text so the accumulator flushes.
	prefix := strings.Repeat("t", tokenSuffixLen+10)
	sseInput := makeSSEThinkingDelta(prefix+token+" end") + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("thinking_delta token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("unreplaced token in thinking_delta output:\n%s", got)
	}
}

// TestStreamingDeanonymizeCRLFLineEndings verifies that \r\n line endings
// round-trip correctly.
func TestStreamingDeanonymizeCRLFLineEndings(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("c", tokenSuffixLen+10)
	// Build SSE with \r\n line endings.
	sseInput := makeSSETextDelta(prefix + token + " end")
	sseInput = strings.ReplaceAll(sseInput, "\n", "\r\n") + "\r\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("CRLF: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("CRLF: unreplaced token in output:\n%s", got)
	}
}

// TestStreamingDeanonymizeMultipleTokensInOneDelta verifies that two PII
// tokens in a single text_delta event are both replaced.
func TestStreamingDeanonymizeMultipleTokensInOneDelta(t *testing.T) {
	token1 := "[PII_EMAIL_c160f8cc]"
	original1 := "alice@example.com"
	token2 := "[PII_PHONE_deadbeef]"
	original2 := "555-867-5309"
	tokenMap := map[string]string{token1: original1, token2: original2}

	prefix := strings.Repeat("m", tokenSuffixLen+10)
	sseInput := makeSSETextDelta(prefix+token1+" and "+token2+" end") + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original1) {
		t.Errorf("first token not replaced:\n%s", got)
	}
	if !strings.Contains(got, original2) {
		t.Errorf("second token not replaced:\n%s", got)
	}
	if strings.Contains(got, token1) || strings.Contains(got, token2) {
		t.Errorf("unreplaced tokens in output:\n%s", got)
	}
}

// --- Issue #55: EOF flush when no tokens matched ---

// TestStreamingDeanonymizeNoTokenMatchShortResponse reproduces issue #55:
// when a session has tokens but the model response contains none of the
// replacement placeholders and the total text is shorter than tokenSuffixLen,
// the client must still receive the full response text.
func TestStreamingDeanonymizeNoTokenMatchShortResponse(t *testing.T) {
	// Session has a token, but the response text contains no placeholders.
	tokenMap := map[string]string{"[PII_EMAIL_c160f8cc]": "[PII_EMAIL_357a20e8]"}

	sseInput := makeSSETextDelta("Hello world") +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, "Hello world") {
		t.Errorf("issue #55: short response without token match lost:\n%s", got)
	}
	if !strings.Contains(got, "message_stop") {
		t.Errorf("issue #55: message_stop not forwarded:\n%s", got)
	}
}

// TestStreamingDeanonymizeNoTokenMatchMultiDelta reproduces issue #55 with
// multiple short text_delta events that individually and cumulatively stay
// under tokenSuffixLen.
func TestStreamingDeanonymizeNoTokenMatchMultiDelta(t *testing.T) {
	tokenMap := map[string]string{"[PII_PHONE_deadbeef]": "555-0100"}

	sseInput := makeSSETextDelta("Hi") +
		makeSSETextDelta(" there") +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, "Hi") || !strings.Contains(got, "there") {
		t.Errorf("issue #55: multi-delta short response lost:\n%s", got)
	}
}

// --- Coverage gap tests ---

// TestSessionTokenCount covers the 0%-covered SessionTokenCount method.
func TestSessionTokenCount(t *testing.T) {
	a := newTestAnonymizer()

	// Empty sessionID returns 0.
	if n := a.SessionTokenCount(""); n != 0 {
		t.Errorf("empty sessionID: got %d, want 0", n)
	}
	// Unknown sessionID returns 0.
	if n := a.SessionTokenCount("unknown"); n != 0 {
		t.Errorf("unknown sessionID: got %d, want 0", n)
	}
	// Inject tokens and verify count.
	a.sessionMu.Lock()
	a.sessions["s1"] = map[string]string{"[PII_EMAIL_aaa]": "a@b.com", "[PII_PHONE_bbb]": "555-1234"}
	a.sessionMu.Unlock()
	if n := a.SessionTokenCount("s1"); n != 2 {
		t.Errorf("s1: got %d, want 2", n)
	}
}

// TestSetPIIInstructions covers the 0%-covered setter.
func TestSetPIIInstructions(t *testing.T) {
	a := newTestAnonymizer()
	custom := map[string]string{
		"claude": "Custom Claude instruction",
		"gpt":    "Custom GPT instruction",
	}
	a.SetPIIInstructions(custom)

	// Prefix match should return the custom instruction.
	got := a.resolvePIIInstruction("claude-3-opus")
	if got != "Custom Claude instruction" {
		t.Errorf("prefix match failed: got %q", got)
	}
}

// TestResolvePIIInstructionFallbacks covers the untested branches of
// resolvePIIInstruction: default key fallback and hardcoded fallback.
func TestResolvePIIInstructionFallbacks(t *testing.T) {
	a := newTestAnonymizer()

	// No piiInstructions set → hardcoded default.
	got := a.resolvePIIInstruction("some-model")
	if got != defaultPIIInstruction {
		t.Errorf("expected hardcoded default, got %q", got)
	}

	// With "default" key, no prefix match → default key wins.
	a.SetPIIInstructions(map[string]string{"default": "fallback instruction"})
	got = a.resolvePIIInstruction("unknown-model")
	if got != "fallback instruction" {
		t.Errorf("expected fallback instruction, got %q", got)
	}

	// Empty map → hardcoded default again.
	a.SetPIIInstructions(map[string]string{})
	got = a.resolvePIIInstruction("any")
	if got != defaultPIIInstruction {
		t.Errorf("expected hardcoded default with empty map, got %q", got)
	}
}

// TestDeleteSessionEmptyID covers the empty-sessionID guard in DeleteSession.
func TestDeleteSessionEmptyID(t *testing.T) {
	a := newTestAnonymizer()
	// Inject a session to confirm it's not accidentally deleted.
	a.sessionMu.Lock()
	a.sessions["keep"] = map[string]string{"tok": "val"}
	a.sessionMu.Unlock()

	a.DeleteSession("") // should be a no-op

	a.sessionMu.RLock()
	if _, ok := a.sessions["keep"]; !ok {
		t.Error("DeleteSession('') removed an unrelated session")
	}
	a.sessionMu.RUnlock()
}

// TestProcessLineSSEComment covers the SSE comment passthrough in processLine.
func TestProcessLineSSEComment(t *testing.T) {
	tokenMap := map[string]string{"[PII_EMAIL_c160f8cc]": "alice@example.com"}
	sseInput := ": this is an SSE comment\n" +
		makeSSETextDelta(strings.Repeat("x", tokenSuffixLen+5)+"hello") + "\n"
	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, ": this is an SSE comment") {
		t.Errorf("SSE comment not passed through:\n%s", got)
	}
}

// TestProcessLineNonDataLine covers the non-"data:" line path (e.g. "event:" lines).
func TestProcessLineNonDataLine(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := "event: content_block_delta\n" +
		makeSSETextDelta(strings.Repeat("n", tokenSuffixLen+5)+token+" end") + "\n"
	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, "event: content_block_delta") {
		t.Errorf("event line not passed through:\n%s", got)
	}
}

// TestProcessLineInvalidJSON covers the JSON parse error fallback in processLine.
func TestProcessLineInvalidJSON(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := "data: {not valid json " + token + "}\n\n"
	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("token in malformed JSON not replaced:\n%s", got)
	}
}

// errorReader returns an error after delivering n bytes.
type errorReader struct {
	data []byte
	pos  int
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, r.err
	}
	return n, nil
}

func (r *errorReader) Close() error { return nil }

// TestHandleStreamEndNonEOFError covers the non-EOF error path in handleStreamEnd.
func TestHandleStreamEndNonEOFError(t *testing.T) {
	a := newTestAnonymizer()
	a.SetVerbose(false)
	sessionID := "err-session"
	a.sessionMu.Lock()
	a.sessions[sessionID] = map[string]string{}
	a.sessionMu.Unlock()

	errFail := errors.New("connection reset")
	src := &errorReader{
		data: []byte(makeSSETextDelta("hello world")),
		err:  errFail,
	}

	rc := a.StreamingDeanonymize(src, sessionID)
	_, err := io.ReadAll(rc)
	if err == nil {
		t.Fatal("expected error from non-EOF read failure, got nil")
	}
	if !strings.Contains(err.Error(), "connection reset") {
		t.Errorf("expected 'connection reset' error, got: %v", err)
	}
}

// TestStreamingDeanonymizeVerboseLogging covers the verbose logging path in
// processTextDelta when a token replacement actually occurs.
func TestStreamingDeanonymizeVerboseLogging(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	a := newTestAnonymizer()
	a.SetVerbose(true) // enable verbose path
	sessionID := "verbose-session"
	a.sessionMu.Lock()
	a.sessions[sessionID] = tokenMap
	a.sessionMu.Unlock()

	prefix := strings.Repeat("v", tokenSuffixLen+10)
	sseInput := makeSSETextDelta(prefix+token+" end") + "\n"
	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID)
	defer rc.Close() //nolint:errcheck

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if !strings.Contains(string(got), original) {
		t.Errorf("verbose path: token not replaced:\n%s", string(got))
	}
}

// TestFlushRemainderUsesLastIndex verifies that flushRemainder emits the
// content block index from the last-seen text_delta, not a hardcoded value.
func TestFlushRemainderUsesLastIndex(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	// Build a thinking_delta at index 0 — the flush should use index 0.
	env := sseEnvelope{
		Type:  "content_block_delta",
		Index: 3,
		Delta: &sseDelta{Type: "text_delta", Text: "Hello " + token},
	}
	b, _ := json.Marshal(env)
	sseInput := "data: " + string(b) + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	// The synthetic flush event should carry "index":3.
	if !strings.Contains(got, `"index":3`) {
		t.Errorf("flush did not use lastIndex=3:\n%s", got)
	}
}

// TestStreamingDeanonymizeEmptySession verifies behavior when the session
// has no tokens — output should pass through unchanged.
func TestStreamingDeanonymizeEmptySession(t *testing.T) {
	got := readStreamResult(t, makeSSETextDelta(strings.Repeat("z", tokenSuffixLen+5)+"plain text")+"\n", map[string]string{})
	if !strings.Contains(got, "plain text") {
		t.Errorf("plain text not in output:\n%s", got)
	}
}

// TestStreamingDeanonymizeThreeChunkSplit verifies that a token whose bytes
// span three separate text_delta events is correctly reassembled and replaced.
func TestStreamingDeanonymizeThreeChunkSplit(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc]"
	original := "alice@example.com"
	tokenMap := map[string]string{token: original}

	// Split token into three parts: first byte, middle, last byte.
	part1 := token[:1]
	part2 := token[1 : len(token)-1]
	part3 := token[len(token)-1:]

	prefix := strings.Repeat("x", tokenSuffixLen+10)
	sseInput := makeSSETextDelta(prefix+part1) +
		makeSSETextDelta(part2) +
		makeSSETextDelta(part3+" tail") + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("three-chunk split: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("three-chunk split: unreplaced token:\n%s", got)
	}
}

// TestStreamingDeanonymizeTokenMapMiss verifies that an unknown token (not in
// the session map) passes through the stream unchanged.
func TestStreamingDeanonymizeTokenMapMiss(t *testing.T) {
	knownToken := "[PII_EMAIL_c160f8cc]"
	unknownToken := "[PII_PHONE_ffffffff]"
	tokenMap := map[string]string{knownToken: "alice@example.com"}

	prefix := strings.Repeat("u", tokenSuffixLen+10)
	sseInput := makeSSETextDelta(prefix+unknownToken+" end") + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, unknownToken) {
		t.Errorf("unknown token should pass through unchanged:\n%s", got)
	}
}
