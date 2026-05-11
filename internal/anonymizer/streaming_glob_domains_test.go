package anonymizer

import (
	"strings"
	"testing"
)

// TestAzureOpenAIStreamingDeanonymize verifies that an OpenAI-format SSE
// stream routed through an Azure OpenAI domain (matched by the
// *.openai.azure.com glob) is correctly deanonymized.
func TestAzureOpenAIStreamingDeanonymize(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("a", tokenSuffixLen+10)
	sseInput := makeOpenAITextDelta(prefix+token+" end") +
		makeOpenAIFinishChunk() +
		"data: [DONE]\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, "myresource.openai.azure.com")

	if !strings.Contains(got, original) {
		t.Errorf("Azure OpenAI: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Azure OpenAI: unreplaced token:\n%s", got)
	}
}

// TestVertexAIStreamingDeanonymize verifies that a Gemini-format SSE stream
// routed through a domain matching the *.aiplatform.googleapis.com glob is
// correctly deanonymized.
//
// NOTE: real Vertex regional URLs use hyphens
// ({region}-aiplatform.googleapis.com) and have only 3 DNS labels, so they
// do NOT match the 4-label *.aiplatform.googleapis.com glob under strict
// segment-glob. This test uses a synthetic 4-label domain to exercise the
// glob-routed path. See PR description for the recommendation to
// users with regional Vertex endpoints.
func TestVertexAIStreamingDeanonymize(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("v", tokenSuffixLen+10)
	// makeGeminiEmptyCandidates() acts as a stream terminator.
	sseInput := makeGeminiTextDelta(prefix+token+" end") +
		makeGeminiEmptyCandidates() +
		"\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, "region.aiplatform.googleapis.com")

	if !strings.Contains(got, original) {
		t.Errorf("Vertex AI: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Vertex AI: unreplaced token:\n%s", got)
	}
}

// TestBedrockStreamingDeanonymize verifies passthrough deanonymization
// across multiple AWS regions for the bedrock-runtime infix glob.
// Three regions are tested as continental representatives (US, EU, APAC) —
// the wildcard matcher itself is exhaustively tested in the domainmatch
// package. This loop verifies that the matched domain reaches the right
// Provider (passthrough) regardless of which AWS region fills the wildcard.
func TestBedrockStreamingDeanonymize(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	// Bedrock SSE format varies by model. Use a generic payload to test
	// passthrough raw replacement.
	sseInput := "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello " + token + "\"}}\n\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	for _, region := range []string{"us-east-1", "eu-west-1", "ap-southeast-1"} {
		domain := "bedrock-runtime." + region + ".amazonaws.com"
		t.Run(region, func(t *testing.T) {
			got := readStreamResultForDomain(t, sseInput, tokenMap, domain)
			if !strings.Contains(got, original) {
				t.Errorf("Bedrock %s: token not replaced:\n%s", region, got)
			}
			if strings.Contains(got, token) {
				t.Errorf("Bedrock %s: unreplaced token:\n%s", region, got)
			}
		})
	}
}

// TestBedrockAgentStreamingDeanonymize covers the bedrock-agent-runtime
// infix glob, which uses a different SSE shape from invoke-model.
func TestBedrockAgentStreamingDeanonymize(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := "data: {\"output\":{\"text\":\"Contact " + token + " for details\"}}\n\n"

	got := readStreamResultForDomain(t, sseInput, tokenMap, "bedrock-agent-runtime.us-east-1.amazonaws.com")
	if !strings.Contains(got, original) {
		t.Errorf("Bedrock Agent: token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("Bedrock Agent: unreplaced token:\n%s", got)
	}
}
