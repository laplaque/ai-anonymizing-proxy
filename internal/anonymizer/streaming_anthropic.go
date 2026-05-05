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

// agentContentBlock represents a text block within a Managed Agents event.
type agentContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// agentEventEnvelope parses agent-level SSE events from the Managed Agents API.
// Events like agent.message and agent.tool_result carry content arrays with text.
type agentEventEnvelope struct {
	Type    string              `json:"type"`
	ID      string              `json:"id"`
	Content []agentContentBlock `json:"content,omitempty"`
	Input   json.RawMessage     `json:"input,omitempty"`
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

	// Managed Agents API events: extract and replace text in content blocks.
	if strings.HasPrefix(envelope.Type, "agent.") {
		a.Flush()
		return a.processAgentEvent(payload)
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

// processAgentEvent handles Managed Agents API events (agent.message,
// agent.tool_result, agent.mcp_tool_result, agent.tool_use, etc.).
// Events with content[] arrays get targeted text replacement; tool_use events
// get raw replacement on the serialized input; all others pass through with
// raw replacement on the full payload.
func (a *anthropicDeanonymizer) processAgentEvent(payload []byte) bool {
	var agent agentEventEnvelope
	if err := json.Unmarshal(payload, &agent); err != nil {
		return false
	}

	switch agent.Type {
	case "agent.message", "agent.tool_result", "agent.mcp_tool_result":
		return a.processAgentContentEvent(payload, &agent)
	case "agent.tool_use", "agent.custom_tool_use", "agent.mcp_tool_use":
		return a.processAgentInputEvent(payload, &agent)
	default:
		// agent.thinking and other unknown agent.* events — no text to accumulate.
		writePipe(a.opts.pw,
			[]byte(a.opts.replacer.Replace(sseDataPrefix+string(payload))),
			[]byte("\n"))
		return true
	}
}

// processAgentContentEvent replaces PII tokens in content[].text fields of
// agent.message, agent.tool_result, and agent.mcp_tool_result events.
// It uses raw JSON patching on individual content blocks to preserve all
// fields on non-text block types (image, document, etc.).
func (a *anthropicDeanonymizer) processAgentContentEvent(payload []byte, _ *agentEventEnvelope) bool {
	// Parse the envelope as raw map to preserve all top-level fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return false
	}

	contentRaw, ok := raw["content"]
	if !ok {
		writePipe(a.opts.pw, []byte(sseDataPrefix), payload, []byte("\n"))
		return true
	}

	var blocks []json.RawMessage
	if err := json.Unmarshal(contentRaw, &blocks); err != nil || len(blocks) == 0 {
		writePipe(a.opts.pw, []byte(sseDataPrefix), payload, []byte("\n"))
		return true
	}

	replaced := false
	for i, block := range blocks {
		var blockMap map[string]json.RawMessage
		if err := json.Unmarshal(block, &blockMap); err != nil {
			continue
		}
		typeRaw, hasType := blockMap["type"]
		textRaw, hasText := blockMap["text"]
		if !hasType || !hasText {
			continue
		}

		var blockType, blockText string
		if err := json.Unmarshal(typeRaw, &blockType); err != nil || blockType != "text" {
			continue
		}
		if err := json.Unmarshal(textRaw, &blockText); err != nil || blockText == "" {
			continue
		}

		newText := a.opts.replacer.Replace(blockText)
		if newText == blockText {
			continue
		}

		replaced = true
		newTextBytes, _ := json.Marshal(newText)
		blockMap["text"] = newTextBytes
		blocks[i], _ = json.Marshal(blockMap)
	}

	if !replaced {
		writePipe(a.opts.pw, []byte(sseDataPrefix), payload, []byte("\n"))
		return true
	}

	contentBytes, _ := json.Marshal(blocks)
	raw["content"] = contentBytes
	out, _ := json.Marshal(raw)
	writePipe(a.opts.pw, []byte(sseDataPrefix), out, []byte("\n"))

	if a.opts.verbose {
		log.Printf("[DEANON] agent content replaced: sessionID=%s type=%s", a.opts.sessionID, raw["type"])
	}
	return true
}

// processAgentInputEvent replaces PII tokens in the input field of
// agent.tool_use, agent.custom_tool_use, and agent.mcp_tool_use events.
// It parses input as a JSON object, walks all string values with the
// replacer, and re-serializes to preserve JSON validity when restored
// PII values contain special characters.
func (a *anthropicDeanonymizer) processAgentInputEvent(payload []byte, agent *agentEventEnvelope) bool {
	if len(agent.Input) == 0 {
		writePipe(a.opts.pw, []byte(sseDataPrefix), payload, []byte("\n"))
		return true
	}

	var inputMap map[string]any
	if err := json.Unmarshal(agent.Input, &inputMap); err != nil {
		// Not a JSON object — fall back to raw replacement on the full payload.
		writePipe(a.opts.pw,
			[]byte(a.opts.replacer.Replace(sseDataPrefix+string(payload))),
			[]byte("\n"))
		return true
	}

	replaced := replaceStringValues(inputMap, a.opts.replacer)
	if !replaced {
		writePipe(a.opts.pw, []byte(sseDataPrefix), payload, []byte("\n"))
		return true
	}

	// Patch the input field in a raw map to preserve all other envelope fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		writePipe(a.opts.pw, []byte(sseDataPrefix), payload, []byte("\n"))
		return true
	}
	inputBytes, _ := json.Marshal(inputMap)
	raw["input"] = inputBytes
	out, _ := json.Marshal(raw)
	writePipe(a.opts.pw, []byte(sseDataPrefix), out, []byte("\n"))

	if a.opts.verbose {
		log.Printf("[DEANON] agent input replaced: sessionID=%s type=%s", a.opts.sessionID, agent.Type)
	}
	return true
}

// replaceStringValues recursively walks a parsed JSON object and applies
// the replacer to all string values. Returns true if any value was changed.
func replaceStringValues(obj map[string]any, replacer *strings.Replacer) bool {
	changed := false
	for k, v := range obj {
		switch val := v.(type) {
		case string:
			replaced := replacer.Replace(val)
			if replaced != val {
				obj[k] = replaced
				changed = true
			}
		case map[string]any:
			if replaceStringValues(val, replacer) {
				changed = true
			}
		case []any:
			if replaceSliceValues(val, replacer) {
				changed = true
			}
		}
	}
	return changed
}

// replaceSliceValues recursively walks a JSON array and applies the
// replacer to all string values. Returns true if any value was changed.
func replaceSliceValues(arr []any, replacer *strings.Replacer) bool {
	changed := false
	for i, v := range arr {
		switch val := v.(type) {
		case string:
			replaced := replacer.Replace(val)
			if replaced != val {
				arr[i] = replaced
				changed = true
			}
		case map[string]any:
			if replaceStringValues(val, replacer) {
				changed = true
			}
		case []any:
			if replaceSliceValues(val, replacer) {
				changed = true
			}
		}
	}
	return changed
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
