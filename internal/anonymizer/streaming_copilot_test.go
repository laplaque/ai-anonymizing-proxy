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

// TestCopilotPassthroughTokenSplit verifies that the passthrough provider
// at minimum does not crash when a token is split across SSE lines.
// Passthrough is best-effort — cross-line splits may or may not be replaced
// depending on the accumulator; this test documents that no crash occurs.
func TestCopilotPassthroughTokenSplit(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	mid := len(token) / 2
	prefix := strings.Repeat("c", tokenSuffixLen+10)
	sseInput := "data: " + prefix + token[:mid] + "\n" +
		"data: " + token[mid:] + " end\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, copilotDomain)

	if got == "" {
		t.Error("Copilot passthrough: empty output")
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
