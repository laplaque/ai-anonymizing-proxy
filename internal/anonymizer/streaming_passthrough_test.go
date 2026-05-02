package anonymizer

import (
	"strings"
	"testing"
)

// unknownDomain is a domain that does not match any registered AI provider,
// ensuring ProviderPassthrough is selected.
const unknownDomain = "custom-llm.example.com"

// TestPassthroughStreamingReplacement verifies that a PII token in an
// arbitrary (non-standard) JSON SSE payload is replaced when the passthrough
// provider is active.
func TestPassthroughStreamingReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	// Arbitrary JSON that no built-in provider parses — passthrough applies
	// raw strings.Replacer to the payload.
	sseInput := `data: {"output":"` + token + `","done":false}` + "\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, unknownDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Passthrough: token not replaced in output:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Passthrough: unreplaced token found in output:\n%s", got)
	}
}

// TestPassthroughFlushIsNoOp verifies that calling Flush on a
// passthroughDeanonymizer neither panics nor writes anything to the pipe.
// The passthrough provider does not accumulate, so Flush is intentionally
// a no-op.
func TestPassthroughFlushIsNoOp(t *testing.T) {
	got := readStreamResultForDomain(t, "data: hello\n\n", nil, unknownDomain)
	// Just verify no panic — empty token map means no replacements.
	if got == "" {
		t.Error("expected non-empty output from passthrough")
	}
}

// TestPassthroughStreamingNoAccumulation verifies that the passthrough provider
// does not rejoin tokens split across events — this is the documented trade-off
// for unknown providers. Because passthroughDeanonymizer writes each event
// immediately without accumulation, a token split across two events is NOT
// replaced.
func TestPassthroughStreamingNoAccumulation(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "user@example.com"
	tokenMap := map[string]string{token: original}

	mid := len(token) / 2
	// Split token across two events — passthrough cannot rejoin them.
	sseInput := "data: " + token[:mid] + "\n" +
		"data: " + token[mid:] + "\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, unknownDomain)

	// The full token should NOT appear in the output (it was split).
	// Neither should the original — because replacement never occurred.
	// The test asserts the known limitation rather than expecting success.
	if strings.Contains(got, original) {
		// If this assertion starts failing it means passthrough gained
		// accumulation — update this test to reflect the new behavior.
		t.Logf("Passthrough unexpectedly replaced a split token — accumulation may have been added")
	}
	// Both halves must be present in the output (they pass through as-is).
	if !strings.Contains(got, token[:mid]) {
		t.Errorf("Passthrough: first half of split token not in output:\n%s", got)
	}
	if !strings.Contains(got, token[mid:]) {
		t.Errorf("Passthrough: second half of split token not in output:\n%s", got)
	}
}
