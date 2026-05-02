package anonymizer

import (
	"encoding/json"
	"log"
	"strings"
)

// sseEnvelope is the minimal structure needed to identify text_delta events
// in an Anthropic SSE stream.
type sseEnvelope struct {
	Type  string    `json:"type"`
	Delta *sseDelta `json:"delta"`
	Index int       `json:"index"`
}

type sseDelta struct {
	Type        string `json:"type"`
	Text        string `json:"text"`
	PartialJSON string `json:"partial_json,omitempty"`
}

// anthropicDeanonymizer handles Anthropic's SSE format: content_block_delta
// events with text_delta, thinking_delta, and input_json_delta sub-types.
type anthropicDeanonymizer struct {
	opts          streamDeanonymizerOpts
	textAccum     strings.Builder
	jsonAccum     strings.Builder
	lastIndex     int // content block index from the most recent text_delta
	lastJSONIndex int // content block index from the most recent input_json_delta
}

func newAnthropicDeanonymizer(opts streamDeanonymizerOpts) *anthropicDeanonymizer {
	return &anthropicDeanonymizer{opts: opts}
}

// ProcessDataPayload parses an Anthropic SSE JSON payload and dispatches
// to the appropriate accumulator.
func (a *anthropicDeanonymizer) ProcessDataPayload(payload []byte) bool {
	var envelope sseEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false
	}

	isDeltaText := envelope.Type == "content_block_delta" &&
		envelope.Delta != nil &&
		(envelope.Delta.Type == "text_delta" || envelope.Delta.Type == "thinking_delta")

	isJSONDelta := envelope.Type == "content_block_delta" &&
		envelope.Delta != nil &&
		envelope.Delta.Type == "input_json_delta"

	if isDeltaText {
		a.processTextDelta(&envelope)
		return true
	}

	if isJSONDelta {
		a.processJSONDelta(&envelope)
		return true
	}

	// Non-delta event: flush accumulators, then pass through with replacement.
	a.Flush()
	writePipe(a.opts.pw,
		[]byte(a.opts.replacer.Replace(sseDataPrefix+string(payload))),
		[]byte("\n"))
	return true
}

// processTextDelta accumulates text from a text_delta or thinking_delta event
// and flushes safe prefixes with token replacement.
//
// json.Marshal on *sseEnvelope (string/int/*sseDelta fields) never returns an
// error, so this function is infallible and has no error return.
func (a *anthropicDeanonymizer) processTextDelta(envelope *sseEnvelope) {
	a.lastIndex = envelope.Index
	a.textAccum.WriteString(envelope.Delta.Text)
	accumulated := a.textAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return
	}

	toReplace := accumulated[:flushUpTo]
	replaced := a.opts.replacer.Replace(toReplace)
	if toReplace != replaced && a.opts.verbose {
		log.Printf("[DEANON] text replaced: sessionID=%s tokens=%d", a.opts.sessionID, a.opts.tokenCount)
	}

	envelope.Delta.Text = replaced
	newPayload, _ := json.Marshal(envelope) // error impossible: only string/int fields

	writePipe(a.opts.pw, []byte(sseDataPrefix), newPayload, []byte("\n"))

	remaining := accumulated[flushUpTo:]
	a.textAccum.Reset()
	a.textAccum.WriteString(remaining)
}

// processJSONDelta accumulates partial_json from an input_json_delta event
// and flushes safe prefixes with token replacement.
//
// json.Marshal on *sseEnvelope (string/int/*sseDelta fields) never returns an
// error, so this function is infallible and has no error return.
func (a *anthropicDeanonymizer) processJSONDelta(envelope *sseEnvelope) {
	a.lastJSONIndex = envelope.Index
	a.jsonAccum.WriteString(envelope.Delta.PartialJSON)
	accumulated := a.jsonAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return
	}

	toReplace := accumulated[:flushUpTo]
	replaced := a.opts.replacer.Replace(toReplace)
	if toReplace != replaced && a.opts.verbose {
		log.Printf("[DEANON] json replaced: sessionID=%s tokens=%d", a.opts.sessionID, a.opts.tokenCount)
	}

	envelope.Delta.PartialJSON = replaced
	newPayload, _ := json.Marshal(envelope) // error impossible: only string/int fields

	writePipe(a.opts.pw, []byte(sseDataPrefix), newPayload, []byte("\n"))

	remaining := accumulated[flushUpTo:]
	a.jsonAccum.Reset()
	a.jsonAccum.WriteString(remaining)
}

// Flush emits any remaining accumulated text and JSON with token replacement.
func (a *anthropicDeanonymizer) Flush() {
	a.flushText()
	a.flushJSON()
}

func (a *anthropicDeanonymizer) flushText() {
	if a.textAccum.Len() == 0 {
		return
	}
	flushed := a.opts.replacer.Replace(a.textAccum.String())
	if flushed != "" {
		synth := map[string]any{
			"type":  "content_block_delta",
			"index": a.lastIndex,
			"delta": map[string]string{"type": "text_delta", "text": flushed},
		}
		if b, err := json.Marshal(synth); err == nil {
			writePipe(a.opts.pw, []byte(sseDataPrefix), b, []byte("\n\n"))
		}
	}
	a.textAccum.Reset()
}

func (a *anthropicDeanonymizer) flushJSON() {
	if a.jsonAccum.Len() == 0 {
		return
	}
	flushed := a.opts.replacer.Replace(a.jsonAccum.String())
	if flushed != "" {
		synth := map[string]any{
			"type":  "content_block_delta",
			"index": a.lastJSONIndex,
			"delta": map[string]string{"type": "input_json_delta", "partial_json": flushed},
		}
		if b, err := json.Marshal(synth); err == nil {
			writePipe(a.opts.pw, []byte(sseDataPrefix), b, []byte("\n\n"))
		}
	}
	a.jsonAccum.Reset()
}
