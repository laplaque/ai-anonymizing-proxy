package anonymizer

import (
	"io"
	"strings"
	"testing"
)

// readStreamResultForDomain is the shared helper used by all provider test files.
// It wires a pre-populated session into a fresh Anonymizer and runs
// StreamingDeanonymize against the given domain, returning the full output.
func readStreamResultForDomain(t *testing.T, sseInput string, tokenMap map[string]string, domain string) string {
	t.Helper()
	a := newTestAnonymizer()
	a.SetVerbose(false)
	sessionID := "test-session"
	a.sessionMu.Lock()
	a.sessions[sessionID] = tokenMap
	a.sessionMu.Unlock()
	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID, domain)
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	return string(got)
}

// readStreamResultVerbose is like readStreamResultForDomain but runs with
// verbose logging enabled so the log.Printf branches are exercised.
func readStreamResultVerbose(t *testing.T, sseInput string, tokenMap map[string]string, domain string) string {
	t.Helper()
	a := newTestAnonymizer()
	a.SetVerbose(true)
	sessionID := "verbose-session"
	a.sessionMu.Lock()
	a.sessions[sessionID] = tokenMap
	a.sessionMu.Unlock()
	src := io.NopCloser(strings.NewReader(sseInput))
	rc := a.StreamingDeanonymize(src, sessionID, domain)
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading streaming output: %v", err)
	}
	return string(got)
}

// TestProviderForDomain verifies that every registered domain maps to the
// expected provider and that unknown domains fall back to ProviderPassthrough.
func TestProviderForDomain(t *testing.T) {
	cases := []struct {
		domain string
		want   Provider
	}{
		{"api.anthropic.com", ProviderAnthropic},
		{"api.openai.com", ProviderOpenAI},
		{"api.mistral.ai", ProviderOpenAI},
		{"api.together.xyz", ProviderOpenAI},
		{"api.perplexity.ai", ProviderOpenAI},
		{"api.huggingface.co", ProviderOpenAI},
		{"generativelanguage.googleapis.com", ProviderGemini},
		{"api.cohere.ai", ProviderCohere},
		{"api.replicate.com", ProviderReplicate},
		// New providers (Phase 1)
		{"api.groq.com", ProviderOpenAI},
		{"api.deepseek.com", ProviderOpenAI},
		{"api.fireworks.ai", ProviderOpenAI},
		{"api.x.ai", ProviderOpenAI},
		{"api.endpoints.anyscale.com", ProviderOpenAI},
		{"openrouter.ai", ProviderOpenAI},
		{"api.portkey.ai", ProviderOpenAI},
		// Phase 4: GitHub Copilot proprietary REST format — passthrough
		{"api.githubcopilot.com", ProviderPassthrough},
		// Phase 5: Cloudflare AI Gateway — passthrough (multiple upstream
		// formats behind one domain).
		{"gateway.ai.cloudflare.com", ProviderPassthrough},
		{"GATEWAY.AI.CLOUDFLARE.COM", ProviderPassthrough},
		{"gateway.ai.cloudflare.com.", ProviderPassthrough},
		// Phase 3: prefix wildcards (Azure, Vertex)
		{"myresource.openai.azure.com", ProviderOpenAI},
		{"eastus2.openai.azure.com", ProviderOpenAI},
		// Vertex AI: global endpoint (exact match in domainToProvider).
		{"aiplatform.googleapis.com", ProviderGemini},
		// Vertex AI regional endpoints — 3-label hyphen-prefix form
		// matched by *-aiplatform.googleapis.com.
		{"us-central1-aiplatform.googleapis.com", ProviderGemini},
		{"europe-west1-aiplatform.googleapis.com", ProviderGemini},
		{"us-east4-aiplatform.googleapis.com", ProviderGemini},
		{"asia-northeast1-aiplatform.googleapis.com", ProviderGemini},
		// Defensive 4-label form (also in globProviders).
		{"region.aiplatform.googleapis.com", ProviderGemini},
		{"anything.aiplatform.googleapis.com", ProviderGemini},
		// Case folding (RFC 1035 §2.3.3) — DNS is case-insensitive.
		{"API.Anthropic.com", ProviderAnthropic},
		{"MyResource.OPENAI.azure.com", ProviderOpenAI},
		{"US-EAST4-aiplatform.googleapis.com", ProviderGemini},
		// Trailing-dot canonical form (RFC 1035 §3.1).
		{"api.anthropic.com.", ProviderAnthropic},
		{"us-central1-aiplatform.googleapis.com.", ProviderGemini},
		// Phase 3: infix wildcards (Bedrock)
		{"bedrock-runtime.us-east-1.amazonaws.com", ProviderPassthrough},
		{"bedrock-runtime.eu-west-1.amazonaws.com", ProviderPassthrough},
		{"bedrock-runtime.ap-southeast-1.amazonaws.com", ProviderPassthrough},
		{"bedrock-agent-runtime.us-east-1.amazonaws.com", ProviderPassthrough},
		// Non-matches — must NOT resolve to a glob provider.
		// (passthrough is also the default fallback, but the assertion is
		// that these do not get routed to OpenAI/Gemini despite sharing
		// suffixes with the glob patterns.)
		{"ec2.us-east-1.amazonaws.com", ProviderPassthrough},
		{"s3.amazonaws.com", ProviderPassthrough},
		// Unknown domains must fall back to passthrough.
		{"unknown.example.com", ProviderPassthrough},
		{"", ProviderPassthrough},
		{"localhost:8080", ProviderPassthrough},
	}

	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			got := ProviderForDomain(tc.domain)
			if got != tc.want {
				t.Errorf("ProviderForDomain(%q) = %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

// TestNewStreamingDeanonymizer verifies that the factory returns a non-nil
// implementation for every named Provider value.
func TestNewStreamingDeanonymizer(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()

	opts := streamDeanonymizerOpts{
		pw:         pw,
		replacer:   strings.NewReplacer(),
		sessionID:  "factory-test",
		verbose:    false,
		tokenCount: 0,
	}

	providers := []Provider{
		ProviderAnthropic,
		ProviderOpenAI,
		ProviderGemini,
		ProviderCohere,
		ProviderReplicate,
		ProviderPassthrough,
		Provider("unknown-provider"), // must also return non-nil (passthrough)
	}

	for _, p := range providers {
		t.Run(string(p), func(t *testing.T) {
			d := NewStreamingDeanonymizer(p, opts)
			if d == nil {
				t.Errorf("NewStreamingDeanonymizer(%q) returned nil", p)
			}
		})
	}
}
