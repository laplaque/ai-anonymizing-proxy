package anonymizer

import (
	"encoding/json"
	"log"
	"strings"
)

// openAIEnvelope is the minimal structure for OpenAI chat completion chunks.
//
// Used by: api.openai.com, api.mistral.ai, api.together.xyz,
// api.perplexity.ai, api.huggingface.co, api.deepseek.com
type openAIEnvelope struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Choices []openAIChoice `json:"choices"`
}

type openAIChoice struct {
	Index        int         `json:"index"`
	Delta        openAIDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type openAIDelta struct {
	Role             string `json:"role,omitempty"`
	Content          string `json:"content,omitempty"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

// openAIDeanonymizer handles the OpenAI chat completions SSE format.
//
// DeepSeek's deepseek-reasoner model adds a parallel reasoning_content field
// carrying chain-of-thought text. Reasoning chunks arrive first, then content
// chunks follow; the two never appear in the same chunk. Each is accumulated
// in its own buffer and flushed via a synthetic chunk with the matching field.
type openAIDeanonymizer struct {
	opts           streamDeanonymizerOpts
	textAccum      strings.Builder
	reasoningAccum strings.Builder
	lastID         string // id from the most recent chunk for synthetic events
}

func newOpenAIDeanonymizer(opts streamDeanonymizerOpts) *openAIDeanonymizer {
	return &openAIDeanonymizer{opts: opts}
}

// ProcessDataPayload parses an OpenAI SSE chunk and accumulates content.
func (o *openAIDeanonymizer) ProcessDataPayload(payload []byte) bool {
	var envelope openAIEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false // likely [DONE] sentinel or malformed — let framework handle
	}

	if len(envelope.Choices) == 0 {
		// Usage-only chunk or empty choices — flush and pass through.
		o.Flush()
		writePipe(o.opts.pw,
			[]byte(sseDataPrefix),
			[]byte(o.opts.replacer.Replace(string(payload))),
			[]byte("\n"))
		return true
	}

	o.lastID = envelope.ID
	choice := &envelope.Choices[0]

	// finish_reason set → stream ending, flush and pass through.
	if choice.FinishReason != nil {
		o.Flush()
		writePipe(o.opts.pw,
			[]byte(sseDataPrefix),
			[]byte(o.opts.replacer.Replace(string(payload))),
			[]byte("\n"))
		return true
	}

	// Neither content nor reasoning_content — role-only or other delta — pass through.
	if choice.Delta.Content == "" && choice.Delta.ReasoningContent == "" {
		writePipe(o.opts.pw,
			[]byte(sseDataPrefix),
			[]byte(o.opts.replacer.Replace(string(payload))),
			[]byte("\n"))
		return true
	}

	if choice.Delta.ReasoningContent != "" {
		o.reasoningAccum.WriteString(choice.Delta.ReasoningContent)
		accumulated := o.reasoningAccum.String()

		flushUpTo := safeCutPoint(accumulated)
		if flushUpTo == 0 {
			return true
		}

		toReplace := accumulated[:flushUpTo]
		replaced := o.opts.replacer.Replace(toReplace)
		if toReplace != replaced && o.opts.verbose {
			log.Printf("[DEANON] openai reasoning replaced: sessionID=%s tokens=%d", o.opts.sessionID, o.opts.tokenCount)
		}

		choice.Delta.ReasoningContent = replaced
		newPayload, _ := json.Marshal(envelope) // error impossible: only string/int fields

		writePipe(o.opts.pw, []byte(sseDataPrefix), newPayload, []byte("\n"))

		remaining := accumulated[flushUpTo:]
		o.reasoningAccum.Reset()
		o.reasoningAccum.WriteString(remaining)
		return true
	}

	// Accumulate content text.
	o.textAccum.WriteString(choice.Delta.Content)
	accumulated := o.textAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return true
	}

	toReplace := accumulated[:flushUpTo]
	replaced := o.opts.replacer.Replace(toReplace)
	if toReplace != replaced && o.opts.verbose {
		log.Printf("[DEANON] openai text replaced: sessionID=%s tokens=%d", o.opts.sessionID, o.opts.tokenCount)
	}

	// Re-serialize with replaced content.
	choice.Delta.Content = replaced
	newPayload, _ := json.Marshal(envelope) // error impossible: only string/int fields

	writePipe(o.opts.pw, []byte(sseDataPrefix), newPayload, []byte("\n"))

	remaining := accumulated[flushUpTo:]
	o.textAccum.Reset()
	o.textAccum.WriteString(remaining)
	return true
}

// Flush emits any remaining accumulated reasoning and content as synthetic
// chunks. Reasoning is flushed first to preserve the arrival order DeepSeek
// uses (reasoning phase then content phase).
func (o *openAIDeanonymizer) Flush() {
	if o.reasoningAccum.Len() > 0 {
		flushed := o.opts.replacer.Replace(o.reasoningAccum.String())
		if flushed != "" {
			synth := openAIEnvelope{
				ID:     o.lastID,
				Object: "chat.completion.chunk",
				Choices: []openAIChoice{{
					Index: 0,
					Delta: openAIDelta{ReasoningContent: flushed},
				}},
			}
			if b, err := json.Marshal(synth); err == nil {
				writePipe(o.opts.pw, []byte(sseDataPrefix), b, []byte("\n\n"))
			}
		}
		o.reasoningAccum.Reset()
	}

	if o.textAccum.Len() > 0 {
		flushed := o.opts.replacer.Replace(o.textAccum.String())
		if flushed != "" {
			synth := openAIEnvelope{
				ID:     o.lastID,
				Object: "chat.completion.chunk",
				Choices: []openAIChoice{{
					Index: 0,
					Delta: openAIDelta{Content: flushed},
				}},
			}
			if b, err := json.Marshal(synth); err == nil {
				writePipe(o.opts.pw, []byte(sseDataPrefix), b, []byte("\n\n"))
			}
		}
		o.textAccum.Reset()
	}
}
