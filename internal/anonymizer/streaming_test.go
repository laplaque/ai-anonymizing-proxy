package anonymizer

import (
	"encoding/json"
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
	sseInput := makeSSETextDelta(prefix+original) +
		"data: [DONE]\n\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, "data: [DONE]") {
		t.Errorf("[DONE] terminator not passed through:\n%s", got)
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
