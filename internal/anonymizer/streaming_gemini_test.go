package anonymizer

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// makeGeminiTextDelta builds a single SSE line in Gemini's
// streamGenerateContent format carrying the given text fragment.
func makeGeminiTextDelta(text string) string {
	type part struct {
		Text string `json:"text,omitempty"`
	}
	type content struct {
		Parts []part `json:"parts"`
	}
	type candidate struct {
		Content content `json:"content"`
	}
	type chunk struct {
		Candidates []candidate `json:"candidates"`
	}
	c := chunk{
		Candidates: []candidate{{
			Content: content{
				Parts: []part{{Text: text}},
			},
		}},
	}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

// makeGeminiEmptyCandidates builds a Gemini SSE chunk with an empty
// candidates array, which some implementations send as a stream terminator.
func makeGeminiEmptyCandidates() string {
	type chunk struct {
		Candidates []struct{} `json:"candidates"`
	}
	c := chunk{Candidates: []struct{}{}}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

const geminiDomain = "generativelanguage.googleapis.com"

// TestGeminiStreamingTokenSplit verifies that a PII token split at the midpoint
// across two Gemini chunks is reassembled and replaced correctly.
func TestGeminiStreamingTokenSplit(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("x", tokenSuffixLen+10)
	mid := len(token) / 2
	sseInput := makeGeminiTextDelta(prefix+token[:mid]) +
		makeGeminiTextDelta(token[mid:]+" world") +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, geminiDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Gemini token split: token not replaced in output:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Gemini token split: unreplaced token found in output:\n%s", got)
	}
}

// TestGeminiStreamingEOFFlush verifies that content held in the accumulator
// at EOF is flushed as a synthetic Gemini chunk.
func TestGeminiStreamingEOFFlush(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Short single chunk — stays below tokenSuffixLen, flushed at EOF.
	sseInput := makeGeminiTextDelta("Hello " + token)

	got := readStreamResultForDomain(t, sseInput, tokenMap, geminiDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Gemini EOF flush: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Gemini EOF flush: unreplaced token in output:\n%s", got)
	}
}

// TestGeminiStreamingEmptyCandidates verifies that a chunk with an empty
// candidates array triggers a flush of any accumulated text and is then
// passed through (possibly with raw token replacement).
func TestGeminiStreamingEmptyCandidates(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Accumulate some text, then send an empty-candidates chunk.
	sseInput := makeGeminiTextDelta("hi "+token) +
		makeGeminiEmptyCandidates() +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, geminiDomain)

	// The accumulated token must still be replaced.
	if !strings.Contains(got, original) {
		t.Errorf("Gemini empty candidates: accumulated token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Gemini empty candidates: unreplaced token in output:\n%s", got)
	}
}

// makeGeminiEmptyTextPart builds a Gemini SSE chunk with a candidate whose
// first part has an empty text field. Some Gemini implementations emit this
// to signal the end of generation before a candidates-level stop reason event.
func makeGeminiEmptyTextPart() string {
	type part struct {
		Text string `json:"text,omitempty"`
	}
	type content struct {
		Parts []part `json:"parts"`
	}
	type candidate struct {
		Content content `json:"content"`
	}
	type chunk struct {
		Candidates []candidate `json:"candidates"`
	}
	c := chunk{
		Candidates: []candidate{{
			Content: content{
				Parts: []part{{Text: ""}},
			},
		}},
	}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

// TestGeminiStreamingInvalidJSON verifies that a malformed JSON payload returns
// false from ProcessDataPayload without writing anything, and the framework
// falls back to raw token replacement in processLine.
func TestGeminiStreamingInvalidJSON(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Invalid JSON triggers the json.Unmarshal error path in ProcessDataPayload.
	// The framework's processLine raw-replacement fallback handles the payload.
	sseInput := "data: {not valid json " + token + "}\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, geminiDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Gemini invalid JSON: token not replaced via raw fallback:\n%s", got)
	}
}

// TestGeminiStreamingEmptyTextPart verifies that a chunk whose first part has
// an empty text field is passed through directly without accumulation.
func TestGeminiStreamingEmptyTextPart(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// First accumulate a token, then send a chunk with empty text — the empty
	// chunk should pass through (covering the text=="" branch) and the
	// subsequent EOF flush should replace the accumulated token.
	sseInput := makeGeminiTextDelta("hi "+token) +
		makeGeminiEmptyTextPart() +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, geminiDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Gemini empty text part: accumulated token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Gemini empty text part: unreplaced token in output:\n%s", got)
	}
}

// TestGeminiStreamingVerboseLogging covers the verbose logging path inside
// the accumulation branch when a token replacement occurs in the flush zone.
func TestGeminiStreamingVerboseLogging(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"

	a := newTestAnonymizer()
	a.SetVerbose(true)
	sessionID := "gemini-verbose"
	a.sessionMu.Lock()
	a.sessions[sessionID] = map[string]string{token: original}
	a.sessionMu.Unlock()

	// The token must fall entirely in the flush zone (before the suffix guard).
	// Use a prefix longer than tokenSuffixLen+len(token) so both fit before the guard.
	prefix := strings.Repeat("g", tokenSuffixLen+len(token)+5)
	sseInput := makeGeminiTextDelta(prefix+token) +
		makeGeminiTextDelta(strings.Repeat("h", tokenSuffixLen+5)+"end") +
		"\n"

	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID, geminiDomain)
	defer rc.Close() //nolint:errcheck

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if !strings.Contains(string(got), original) {
		t.Errorf("Gemini verbose: token not replaced:\n%s", string(got))
	}
}
