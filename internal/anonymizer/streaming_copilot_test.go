package anonymizer

import (
	"strings"
	"testing"
)

// copilotDomain is the GitHub Copilot API domain. It is registered with
// ProviderPassthrough because Copilot's proprietary REST format does not
// need a structured SSE parser — raw token replacement handles PII
// deanonymization in any text-based response.
const copilotDomain = "api.githubcopilot.com"

// TestCopilotPassthroughDeanonymize verifies passthrough token replacement
// works on a synthetic Copilot-like SSE response with arbitrary JSON.
//
// Duplicates TestPassthroughStreamingReplacement by design — pins that
// explicit-map registration (api.githubcopilot.com → ProviderPassthrough in
// domainToProvider) is behaviorally identical to fallback registration. If
// a future refactor changes how explicit map entries dispatch versus the
// default, this test catches the regression at the Copilot route directly
// rather than relying on TestProviderForDomain alone.
func TestCopilotPassthroughDeanonymize(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := "data: {\"type\":\"content\",\"body\":\"Hello " + token + " world\"}\n\n" +
		"data: {\"type\":\"done\"}\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, copilotDomain)

	if !strings.Contains(got, original) {
		t.Errorf("Copilot passthrough: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Copilot passthrough: unreplaced token:\n%s", got)
	}
}

// TestCopilotPassthroughTokenSplit pins the documented passthrough contract
// for cross-line token splits via the Copilot route: passthrough is
// best-effort and does NOT rejoin tokens split across SSE events (see
// streaming_passthrough.go — no accumulation between payloads). Both halves
// of the split token must appear in the output as-is, and the original PII
// must NOT appear because replacement could not occur.
//
// Mirrors TestPassthroughStreamingNoAccumulation but routes through the
// explicit api.githubcopilot.com → ProviderPassthrough mapping. A weaker
// "did not crash" assertion would silently pass on a regression that
// swallows output to an empty string.
func TestCopilotPassthroughTokenSplit(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	mid := len(token) / 2
	prefix := strings.Repeat("c", tokenSuffixLen+10)
	sseInput := "data: " + prefix + token[:mid] + "\n" +
		"data: " + token[mid:] + " end\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, copilotDomain)

	if strings.Contains(got, original) {
		// If this fires, passthrough gained cross-event accumulation —
		// update this test (and its sibling in streaming_passthrough_test.go)
		// to reflect the new contract.
		t.Errorf("Copilot passthrough unexpectedly replaced a split token:\n%s", got)
	}
	if !strings.Contains(got, token[:mid]) {
		t.Errorf("Copilot passthrough: first half of split token not in output:\n%s", got)
	}
	if !strings.Contains(got, token[mid:]) {
		t.Errorf("Copilot passthrough: second half of split token not in output:\n%s", got)
	}
}

// TestCopilotNonStreamingAnonymize verifies that non-streaming (buffered)
// request body anonymization works for the Copilot domain. This tests the
// request path, not the response path.
func TestCopilotNonStreamingAnonymize(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-copilot-1"
	body := []byte(`{"messages":[{"role":"user","content":"Fix the bug in test@example.com's config"}]}`)

	anonymized := a.AnonymizeJSON(body, sessionID)
	if strings.Contains(string(anonymized), "test@example.com") {
		t.Errorf("email not anonymized in Copilot request body: %s", anonymized)
	}

	restored := a.DeanonymizeText(string(anonymized), sessionID)
	if !strings.Contains(restored, "test@example.com") {
		t.Errorf("email not restored after deanonymization: %s", restored)
	}
}
