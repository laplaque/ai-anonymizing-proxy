package anonymizer

import (
	"io"
	"strings"

	"ai-anonymizing-proxy/internal/domainmatch"
)

// Provider identifies an AI API provider's SSE streaming format.
type Provider string

const (
	// ProviderAnthropic handles Anthropic SSE: content_block_delta with
	// text_delta, thinking_delta, and input_json_delta event types.
	ProviderAnthropic Provider = "anthropic"

	// ProviderOpenAI handles the OpenAI chat completions SSE format used by
	// OpenAI, Mistral, Together, Perplexity, and Hugging Face.
	ProviderOpenAI Provider = "openai"

	// ProviderGemini handles Google Gemini's streamGenerateContent SSE format.
	ProviderGemini Provider = "gemini"

	// ProviderCohere handles Cohere's event-based streaming format.
	ProviderCohere Provider = "cohere"

	// ProviderReplicate handles Replicate's plain-text SSE format.
	ProviderReplicate Provider = "replicate"

	// ProviderPassthrough applies raw token replacement without JSON parsing.
	ProviderPassthrough Provider = "passthrough"
)

// StreamingDeanonymizer processes provider-specific SSE data payloads.
//
// Each implementation accumulates text fragments across streamed events,
// applies token replacement via a strings.Replacer, and writes re-serialized
// SSE lines (including the "data: " prefix and trailing newline) to the pipe.
type StreamingDeanonymizer interface {
	// ProcessDataPayload handles the bytes after "data: " from a single SSE
	// line. Returns true if the payload was handled (output written or
	// accumulated), false if parsing failed and the caller should fall back
	// to raw token replacement.
	ProcessDataPayload(payload []byte) bool

	// Flush emits any remaining accumulated text with token replacement.
	// Called at stream end (EOF or read error).
	Flush()
}

// domainToProvider maps registered AI API domains to their streaming format.
// OpenAI-compatible providers share ProviderOpenAI.
var domainToProvider = map[string]Provider{
	"api.anthropic.com":                 ProviderAnthropic,
	"api.openai.com":                    ProviderOpenAI,
	"api.mistral.ai":                    ProviderOpenAI,
	"api.together.xyz":                  ProviderOpenAI,
	"api.perplexity.ai":                 ProviderOpenAI,
	"api.huggingface.co":                ProviderOpenAI,
	"generativelanguage.googleapis.com": ProviderGemini,
	"aiplatform.googleapis.com":         ProviderGemini, // Vertex AI global endpoint
	"api.cohere.ai":                     ProviderCohere,
	"api.replicate.com":                 ProviderReplicate,
	"api.groq.com":                      ProviderOpenAI,
	"api.deepseek.com":                  ProviderOpenAI,
	"api.fireworks.ai":                  ProviderOpenAI,
	"api.x.ai":                          ProviderOpenAI,
	"api.endpoints.anyscale.com":        ProviderOpenAI,
	"openrouter.ai":                     ProviderOpenAI,
	"api.portkey.ai":                    ProviderOpenAI,
}

// globProviders maps segment-glob domain patterns to their streaming format.
// Checked after the exact domainToProvider lookup misses.
//
// Bedrock entries use ProviderPassthrough because the SSE format depends
// on the invoked model (Anthropic vs OpenAI-compatible) which is not
// known from the destination domain alone.
//
// Vertex AI uses *-aiplatform.googleapis.com (label-substring wildcard)
// because Google's regional endpoint format is
// {region}-aiplatform.googleapis.com (3 labels, hyphen between region
// and "aiplatform"). The 4-label *.aiplatform.googleapis.com pattern is
// kept defensively for any future host that might publish such a form.
var globProviders = []struct {
	glob     domainmatch.DomainGlob
	provider Provider
}{
	{domainmatch.Parse("*.openai.azure.com"), ProviderOpenAI},
	{domainmatch.Parse("*-aiplatform.googleapis.com"), ProviderGemini},
	{domainmatch.Parse("*.aiplatform.googleapis.com"), ProviderGemini},
	{domainmatch.Parse("bedrock-runtime.*.amazonaws.com"), ProviderPassthrough},
	{domainmatch.Parse("bedrock-agent-runtime.*.amazonaws.com"), ProviderPassthrough},
}

// ProviderForDomain returns the streaming Provider for a given API domain.
// Exact-match domains are checked first, then segment-glob patterns.
// The domain is lowercased and a trailing "." stripped before lookup so
// mixed-case Host headers and FQDN-canonical inputs route the same as
// their canonical form. Unknown domains return ProviderPassthrough.
func ProviderForDomain(domain string) Provider {
	domain = strings.ToLower(domain)
	if len(domain) > 1 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	if p, ok := domainToProvider[domain]; ok {
		return p
	}
	for _, gp := range globProviders {
		if gp.glob.Match(domain) {
			return gp.provider
		}
	}
	return ProviderPassthrough
}

// streamDeanonymizerOpts holds the configuration shared by all provider
// implementations.
type streamDeanonymizerOpts struct {
	pw         *io.PipeWriter
	replacer   *strings.Replacer
	sessionID  string
	verbose    bool
	tokenCount int
}

// NewStreamingDeanonymizer creates the appropriate provider implementation
// for the given Provider.
func NewStreamingDeanonymizer(provider Provider, opts streamDeanonymizerOpts) StreamingDeanonymizer {
	switch provider {
	case ProviderAnthropic:
		return newAnthropicDeanonymizer(opts)
	case ProviderOpenAI:
		return newOpenAIDeanonymizer(opts)
	case ProviderGemini:
		return newGeminiDeanonymizer(opts)
	case ProviderCohere:
		return newCohereDeanonymizer(opts)
	case ProviderReplicate:
		return newReplicateDeanonymizer(opts)
	default:
		return newPassthroughDeanonymizer(opts)
	}
}
