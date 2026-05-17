package anonymizer

import (
	"strings"
	"testing"
)

// cloudflareGatewayDomain is the Cloudflare AI Gateway domain. It is
// registered with ProviderPassthrough because the gateway proxies to
// multiple upstream providers (OpenAI, Anthropic, Google, etc.) behind a
// single domain, with the SSE format determined by the path. The proxy
// routes streaming format by domain only, so passthrough (raw token
// replacement) is the safe default that works regardless of which
// upstream format is in use.
const cloudflareGatewayDomain = "gateway.ai.cloudflare.com"

// TestCloudflarePassthroughDeanonymize verifies passthrough token
// replacement works on the three plausible SSE shapes returned through
// Cloudflare AI Gateway: OpenAI-style (via /compat/ or /openai/),
// Anthropic-style (via /anthropic/), and plain text. The proxy cannot
// distinguish the upstream format from the destination domain, so the
// passthrough deanonymizer must handle all of them.
func TestCloudflarePassthroughDeanonymize(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	tests := []struct {
		name     string
		sseInput string
	}{
		{
			name: "openai_format",
			sseInput: "data: {\"choices\":[{\"delta\":{\"content\":\"Hello " + token + "\"}}]}\n\n" +
				"data: [DONE]\n\n",
		},
		{
			name: "anthropic_format",
			sseInput: "event: content_block_delta\n" +
				"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello " + token + "\"}}\n\n",
		},
		{
			name:     "plain_text",
			sseInput: "data: The email is " + token + "\n\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := readStreamResultForDomain(t, tc.sseInput, tokenMap, cloudflareGatewayDomain)
			if !strings.Contains(got, original) {
				t.Errorf("Cloudflare passthrough %s: token not replaced:\n%s", tc.name, got)
			}
			if strings.Contains(got, token) {
				t.Errorf("Cloudflare passthrough %s: unreplaced token:\n%s", tc.name, got)
			}
		})
	}
}

// TestCloudflareNonStreamingAnonymize verifies that non-streaming
// (buffered) request body anonymization works for a Cloudflare-routed
// request, and that DeanonymizeText restores the original value.
func TestCloudflareNonStreamingAnonymize(t *testing.T) {
	a := newTestAnonymizer()
	sessionID := "sess-cloudflare-1"
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"Summarize the report by test@example.com"}]}`)

	anonymized := a.AnonymizeJSON(body, sessionID)
	if strings.Contains(string(anonymized), "test@example.com") {
		t.Errorf("email not anonymized in Cloudflare request body: %s", anonymized)
	}

	restored := a.DeanonymizeText(string(anonymized), sessionID)
	if !strings.Contains(restored, "test@example.com") {
		t.Errorf("email not restored after deanonymization: %s", restored)
	}
}
