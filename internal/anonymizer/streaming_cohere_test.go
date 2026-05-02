package anonymizer

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// makeCohereContentDelta builds a Cohere SSE line with type "content-delta"
// carrying the given text fragment inside delta.message.content.text.
func makeCohereContentDelta(text string) string {
	type cohereContentInner struct {
		Text string `json:"text,omitempty"`
	}
	type cohereMessageInner struct {
		Content cohereContentInner `json:"content"`
	}
	type cohereDeltaInner struct {
		Message cohereMessageInner `json:"message"`
	}
	type chunk struct {
		Type  string           `json:"type"`
		Index int              `json:"index"`
		Delta cohereDeltaInner `json:"delta"`
	}
	c := chunk{
		Type:  "content-delta",
		Index: 0,
		Delta: cohereDeltaInner{
			Message: cohereMessageInner{
				Content: cohereContentInner{Text: text},
			},
		},
	}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

// makeCohereNonContentEvent builds a Cohere SSE event of the given type that
// does not carry any content (e.g. "stream-start", "message-end").
func makeCohereNonContentEvent(eventType string) string {
	type chunk struct {
		Type string `json:"type"`
	}
	c := chunk{Type: eventType}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

const cohereDomain = "api.cohere.ai"

// TestCohereStreamingTokenSplit verifies that a PII token split at the midpoint
// across two content-delta events is reassembled and replaced.
func TestCohereStreamingTokenSplit(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("x", tokenSuffixLen+10)
	mid := len(token) / 2
	sseInput := makeCohereContentDelta(prefix+token[:mid]) +
		makeCohereContentDelta(token[mid:]+" world") +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, cohereDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Cohere token split: token not replaced in output:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Cohere token split: unreplaced token found in output:\n%s", got)
	}
}

// TestCohereStreamingEOFFlush verifies that content held in the accumulator
// at EOF is flushed as a synthetic content-delta chunk.
func TestCohereStreamingEOFFlush(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Short single chunk — stays below tokenSuffixLen, flushed at EOF.
	sseInput := makeCohereContentDelta("Hello " + token)

	got := readStreamResultForDomain(t, sseInput, tokenMap, cohereDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Cohere EOF flush: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Cohere EOF flush: unreplaced token in output:\n%s", got)
	}
}

// TestCohereStreamingNonContentEvent verifies that a non-content-delta event
// (e.g. "stream-start") triggers a flush of any accumulated text and is then
// passed through with raw token replacement applied.
func TestCohereStreamingNonContentEvent(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Accumulate a token via a content-delta, then send a non-content event.
	sseInput := makeCohereContentDelta("hi " + token) +
		makeCohereNonContentEvent("message-end") +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, cohereDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Cohere non-content event: accumulated token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Cohere non-content event: unreplaced token in output:\n%s", got)
	}
	if !strings.Contains(got, "message-end") {
		t.Errorf("Cohere non-content event: event type not present in output:\n%s", got)
	}
}

// makeCohereEmptyTextDelta builds a Cohere content-delta event whose text
// field is empty. Some Cohere implementations emit this for chunking artefacts.
func makeCohereEmptyTextDelta() string {
	type cohereContentInner struct {
		Text string `json:"text,omitempty"`
	}
	type cohereMessageInner struct {
		Content cohereContentInner `json:"content"`
	}
	type cohereDeltaInner struct {
		Message cohereMessageInner `json:"message"`
	}
	type chunk struct {
		Type  string           `json:"type"`
		Index int              `json:"index"`
		Delta cohereDeltaInner `json:"delta"`
	}
	c := chunk{
		Type:  "content-delta",
		Index: 0,
		Delta: cohereDeltaInner{
			Message: cohereMessageInner{
				Content: cohereContentInner{Text: ""},
			},
		},
	}
	b, _ := json.Marshal(c)
	return "data: " + string(b) + "\n"
}

// TestCohereStreamingInvalidJSON verifies that a malformed JSON payload returns
// false and the framework applies raw token replacement via the processLine
// fallback path.
func TestCohereStreamingInvalidJSON(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := "data: {not valid json " + token + "}\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, cohereDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Cohere invalid JSON: token not replaced via raw fallback:\n%s", got)
	}
}

// TestCohereStreamingEmptyTextDelta verifies that a content-delta event with
// an empty text field is passed through directly without accumulation.
func TestCohereStreamingEmptyTextDelta(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Accumulate a token, send an empty-text content-delta, then EOF flush.
	sseInput := makeCohereContentDelta("hi " + token) +
		makeCohereEmptyTextDelta() +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, cohereDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Cohere empty text delta: accumulated token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Cohere empty text delta: unreplaced token in output:\n%s", got)
	}
}

// TestCohereStreamingVerboseLogging covers the verbose logging branch inside
// the accumulation path when a token replacement occurs in the flush zone.
func TestCohereStreamingVerboseLogging(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"

	a := newTestAnonymizer()
	a.SetVerbose(true)
	sessionID := "cohere-verbose"
	a.sessionMu.Lock()
	a.sessions[sessionID] = map[string]string{token: original}
	a.sessionMu.Unlock()

	// The token must fall entirely in the flush zone. Use a prefix longer than
	// tokenSuffixLen+len(token) to ensure the token is not in the suffix guard.
	prefix := strings.Repeat("c", tokenSuffixLen+len(token)+5)
	sseInput := makeCohereContentDelta(prefix+token) +
		makeCohereContentDelta(strings.Repeat("d", tokenSuffixLen+5)+"end") +
		"\n"

	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID, cohereDomain)
	defer rc.Close() //nolint:errcheck

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	if !strings.Contains(string(got), original) {
		t.Errorf("Cohere verbose: token not replaced:\n%s", string(got))
	}
}
