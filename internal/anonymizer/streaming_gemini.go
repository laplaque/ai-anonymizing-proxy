package anonymizer

import (
	"encoding/json"
	"log"
	"strings"
)

// geminiEnvelope is the minimal structure for Gemini streamGenerateContent
// SSE chunks (with ?alt=sse).
type geminiEnvelope struct {
	Candidates []geminiCandidate `json:"candidates"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text,omitempty"`
}

// geminiDeanonymizer handles Gemini's streamGenerateContent SSE format.
type geminiDeanonymizer struct {
	opts      streamDeanonymizerOpts
	textAccum strings.Builder
}

func newGeminiDeanonymizer(opts streamDeanonymizerOpts) *geminiDeanonymizer {
	return &geminiDeanonymizer{opts: opts}
}

// ProcessDataPayload parses a Gemini SSE chunk and accumulates text.
func (g *geminiDeanonymizer) ProcessDataPayload(payload []byte) bool {
	var envelope geminiEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false
	}

	// No candidates or no parts — pass through.
	if len(envelope.Candidates) == 0 ||
		len(envelope.Candidates[0].Content.Parts) == 0 {
		g.Flush()
		writePipe(g.opts.pw,
			[]byte(sseDataPrefix),
			[]byte(g.opts.replacer.Replace(string(payload))),
			[]byte("\n"))
		return true
	}

	text := envelope.Candidates[0].Content.Parts[0].Text
	if text == "" {
		writePipe(g.opts.pw,
			[]byte(sseDataPrefix),
			[]byte(g.opts.replacer.Replace(string(payload))),
			[]byte("\n"))
		return true
	}

	g.textAccum.WriteString(text)
	accumulated := g.textAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return true
	}

	toReplace := accumulated[:flushUpTo]
	replaced := g.opts.replacer.Replace(toReplace)
	if toReplace != replaced && g.opts.verbose {
		log.Printf("[DEANON] gemini text replaced: sessionID=%s tokens=%d", g.opts.sessionID, g.opts.tokenCount)
	}

	envelope.Candidates[0].Content.Parts[0].Text = replaced
	newPayload, _ := json.Marshal(envelope) // error impossible: only string/int fields

	writePipe(g.opts.pw, []byte(sseDataPrefix), newPayload, []byte("\n"))

	remaining := accumulated[flushUpTo:]
	g.textAccum.Reset()
	g.textAccum.WriteString(remaining)
	return true
}

// Flush emits any remaining accumulated text as a synthetic Gemini chunk.
func (g *geminiDeanonymizer) Flush() {
	if g.textAccum.Len() == 0 {
		return
	}
	flushed := g.opts.replacer.Replace(g.textAccum.String())
	if flushed != "" {
		synth := geminiEnvelope{
			Candidates: []geminiCandidate{{
				Content: geminiContent{
					Parts: []geminiPart{{Text: flushed}},
				},
			}},
		}
		if b, err := json.Marshal(synth); err == nil {
			writePipe(g.opts.pw, []byte(sseDataPrefix), b, []byte("\n\n"))
		}
	}
	g.textAccum.Reset()
}
