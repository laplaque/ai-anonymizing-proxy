package anonymizer

import (
	"strings"
	"testing"
)

// makeReplicatePlainDelta builds a Replicate SSE line with plain text in the
// data field (not JSON). This is Replicate's output event format.
func makeReplicatePlainDelta(text string) string {
	return "data: " + text + "\n"
}

const replicateDomain = "api.replicate.com"

// TestReplicateStreamingTokenSplit verifies that a PII token split at the
// midpoint across two plain-text output events is reassembled and replaced.
func TestReplicateStreamingTokenSplit(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("x", tokenSuffixLen+10)
	mid := len(token) / 2
	sseInput := makeReplicatePlainDelta(prefix+token[:mid]) +
		makeReplicatePlainDelta(token[mid:]+" world") +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, replicateDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Replicate token split: token not replaced in output:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Replicate token split: unreplaced token found in output:\n%s", got)
	}
}

// TestReplicateStreamingEOFFlush verifies that content held in the accumulator
// at EOF is emitted (with replacement) when the source ends.
func TestReplicateStreamingEOFFlush(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Short single event — stays below tokenSuffixLen, flushed at EOF.
	sseInput := makeReplicatePlainDelta("Hello " + token)

	got := readStreamResultForDomain(t, sseInput, tokenMap, replicateDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Replicate EOF flush: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Replicate EOF flush: unreplaced token in output:\n%s", got)
	}
}

// TestReplicateStreamingVerboseLogging exercises the verbose log.Printf branch
// in the Replicate provider's accumulation path.
func TestReplicateStreamingVerboseLogging(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("r", tokenSuffixLen+10)
	sseInput := makeReplicatePlainDelta(prefix+token+" end") + "\n"

	got := readStreamResultVerbose(t, sseInput, tokenMap, replicateDomain)
	if !strings.Contains(got, original) {
		t.Errorf("Replicate verbose: token not replaced:\n%s", got)
	}
}
// ("data: {}") triggers a flush of any pending accumulator content and then
// passes through unchanged.
func TestReplicateStreamingDoneEvent(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Accumulate some text then send the done payload.
	sseInput := makeReplicatePlainDelta("hi " + token) +
		"data: {}\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, replicateDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Replicate done event: accumulated token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Replicate done event: unreplaced token in output:\n%s", got)
	}
	// The done payload itself must appear in the output.
	if !strings.Contains(got, "data: {}") {
		t.Errorf("Replicate done event: done payload not passed through:\n%s", got)
	}
}
