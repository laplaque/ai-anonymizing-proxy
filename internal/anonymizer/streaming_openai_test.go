package anonymizer

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// makeOpenAITextDelta builds a single SSE line carrying an OpenAI
// chat.completion.chunk with the given content fragment.
// finish_reason is left nil to model a normal mid-stream chunk.
func makeOpenAITextDelta(content string) string {
	type delta struct {
		Content string `json:"content,omitempty"`
	}
	type choice struct {
		Index        int     `json:"index"`
		Delta        delta   `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	}
	type chunk struct {
		ID      string   `json:"id"`
		Object  string   `json:"object"`
		Choices []choice `json:"choices"`
	}
	c := chunk{
		ID:     "chatcmpl-test",
		Object: "chat.completion.chunk",
		Choices: []choice{{
			Index:        0,
			Delta:        delta{Content: content},
			FinishReason: nil,
		}},
	}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

// makeOpenAIFinishChunk builds a chunk whose finish_reason is set to "stop",
// signaling the end of the stream.
func makeOpenAIFinishChunk() string {
	reason := "stop"
	type delta struct{}
	type choice struct {
		Index        int     `json:"index"`
		Delta        delta   `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	}
	type chunk struct {
		ID      string   `json:"id"`
		Object  string   `json:"object"`
		Choices []choice `json:"choices"`
	}
	c := chunk{
		ID:     "chatcmpl-test",
		Object: "chat.completion.chunk",
		Choices: []choice{{
			Index:        0,
			FinishReason: &reason,
		}},
	}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

// makeOpenAIRoleOnlyChunk builds the first chunk sent by OpenAI, which carries
// only a role field in the delta and no content.
func makeOpenAIRoleOnlyChunk() string {
	type delta struct {
		Role string `json:"role,omitempty"`
	}
	type choice struct {
		Index        int     `json:"index"`
		Delta        delta   `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	}
	type chunk struct {
		ID      string   `json:"id"`
		Object  string   `json:"object"`
		Choices []choice `json:"choices"`
	}
	c := chunk{
		ID:     "chatcmpl-test",
		Object: "chat.completion.chunk",
		Choices: []choice{{
			Index: 0,
			Delta: delta{Role: "assistant"},
		}},
	}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

const openAIDomain = "api.openai.com"

// TestOpenAIStreamingTokenSplit verifies that a PII token split at the midpoint
// across two content chunks is reassembled and replaced correctly.
func TestOpenAIStreamingTokenSplit(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Enough prefix to push the first half of the token past the suffix guard,
	// triggering a flush that emits the prefix but holds the partial token.
	prefix := strings.Repeat("x", tokenSuffixLen+10)
	mid := len(token) / 2
	sseInput := makeOpenAITextDelta(prefix+token[:mid]) +
		makeOpenAITextDelta(token[mid:]+" world") +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, openAIDomain)

	if !strings.Contains(got, original) {
		t.Errorf("OpenAI token split: token not replaced in output:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("OpenAI token split: unreplaced token found in output:\n%s", got)
	}
}

// TestOpenAIStreamingEOFFlush verifies that content held in the accumulator
// (shorter than tokenSuffixLen) is emitted when the stream ends at EOF.
func TestOpenAIStreamingEOFFlush(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Short content — stays in accumulator until EOF.
	sseInput := makeOpenAITextDelta("Hello " + token)

	got := readStreamResultForDomain(t, sseInput, tokenMap, openAIDomain)

	if !strings.Contains(got, original) {
		t.Errorf("OpenAI EOF flush: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("OpenAI EOF flush: unreplaced token in output:\n%s", got)
	}
}

// TestOpenAIStreamingDoneSentinel verifies that the "data: [DONE]" terminator
// passes through unchanged. The Anthropic deanonymizer returns false for this
// non-JSON payload, falling back to raw replacement in processLine.
func TestOpenAIStreamingDoneSentinel(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("a", tokenSuffixLen+5)
	sseInput := makeOpenAITextDelta(prefix+token) +
		"data: [DONE]\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, openAIDomain)

	if !strings.Contains(got, "data: [DONE]") {
		t.Errorf("OpenAI [DONE]: sentinel not passed through:\n%s", got)
	}
	if !strings.Contains(got, original) {
		t.Errorf("OpenAI [DONE]: token before sentinel not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("OpenAI [DONE]: unreplaced token in output:\n%s", got)
	}
}

// TestOpenAIStreamingRoleOnlyChunk verifies that the first assistant chunk
// (delta with only a role, no content) passes through without disrupting
// subsequent token accumulation.
func TestOpenAIStreamingRoleOnlyChunk(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("r", tokenSuffixLen+5)
	sseInput := makeOpenAIRoleOnlyChunk() +
		makeOpenAITextDelta(prefix+token+" end") +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, openAIDomain)

	if !strings.Contains(got, original) {
		t.Errorf("OpenAI role-only chunk: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("OpenAI role-only chunk: unreplaced token in output:\n%s", got)
	}
}

// TestOpenAIStreamingFinishReason verifies that a chunk with finish_reason set
// triggers a flush of any accumulated text before the stop chunk is emitted.
func TestOpenAIStreamingFinishReason(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Short content — stays in accumulator, then finish chunk triggers flush.
	sseInput := makeOpenAITextDelta("greet "+token) +
		makeOpenAIFinishChunk() +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, openAIDomain)

	if !strings.Contains(got, original) {
		t.Errorf("OpenAI finish_reason flush: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("OpenAI finish_reason flush: unreplaced token in output:\n%s", got)
	}
}

// makeOpenAIEmptyChoicesChunk builds a JSON-valid OpenAI chunk whose choices
// array is empty. This is used by some OpenAI-compatible APIs to send usage
// metadata as a trailing chunk after the last content chunk.
func makeOpenAIEmptyChoicesChunk() string {
	type chunk struct {
		ID      string     `json:"id"`
		Object  string     `json:"object"`
		Choices []struct{} `json:"choices"`
	}
	c := chunk{ID: "chatcmpl-usage", Object: "chat.completion.chunk", Choices: []struct{}{}}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

// TestOpenAIStreamingEmptyChoicesFlush verifies that a usage-only chunk
// (choices == []) triggers a flush of any accumulated text and then passes
// through unchanged.
func TestOpenAIStreamingEmptyChoicesFlush(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Short content accumulates, then the empty-choices chunk triggers a flush.
	sseInput := makeOpenAITextDelta("hi "+token) +
		makeOpenAIEmptyChoicesChunk() +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, openAIDomain)

	if !strings.Contains(got, original) {
		t.Errorf("OpenAI empty choices flush: accumulated token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("OpenAI empty choices flush: unreplaced token in output:\n%s", got)
	}
}

// TestOpenAIStreamingVerboseLogging covers the verbose logging path inside the
// accumulation branch, when a token replacement actually occurs in the flush zone.
func TestOpenAIStreamingVerboseLogging(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"

	a := newTestAnonymizer()
	a.SetVerbose(true)
	sessionID := "openai-verbose"
	a.sessionMu.Lock()
	a.sessions[sessionID] = map[string]string{token: original}
	a.sessionMu.Unlock()

	// The token must fall entirely within the flush zone so that toReplace != replaced.
	// Prefix must be large enough to push the token + its suffix past the suffix guard.
	prefix := strings.Repeat("v", tokenSuffixLen+len(token)+5)
	sseInput := makeOpenAITextDelta(prefix+token) +
		makeOpenAITextDelta(strings.Repeat("w", tokenSuffixLen+5)+"end") +
		"\n"

	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID, openAIDomain)
	defer rc.Close() //nolint:errcheck

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if !strings.Contains(string(got), original) {
		t.Errorf("OpenAI verbose: token not replaced:\n%s", string(got))
	}
}
