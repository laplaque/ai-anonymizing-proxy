package anonymizer

import (
	"encoding/json"
	"log"
	"strings"
)

// cohereEnvelope is the minimal structure for Cohere streaming events.
type cohereEnvelope struct {
	Type  string       `json:"type"`
	Index int          `json:"index,omitempty"`
	Delta *cohereDelta `json:"delta,omitempty"`
}

type cohereDelta struct {
	Message *cohereMessage `json:"message,omitempty"`
}

type cohereMessage struct {
	Content cohereContent `json:"content"`
}

type cohereContent struct {
	Text string `json:"text,omitempty"`
}

// cohereDeanonymizer handles Cohere's event-based streaming format.
type cohereDeanonymizer struct {
	opts      streamDeanonymizerOpts
	textAccum strings.Builder
	lastIndex int
}

func newCohereDeanonymizer(opts streamDeanonymizerOpts) *cohereDeanonymizer {
	return &cohereDeanonymizer{opts: opts}
}

// ProcessDataPayload parses a Cohere SSE event and accumulates content-delta text.
func (c *cohereDeanonymizer) ProcessDataPayload(payload []byte) bool {
	var envelope cohereEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false
	}

	// Only content-delta events carry text to accumulate.
	if envelope.Type != "content-delta" ||
		envelope.Delta == nil ||
		envelope.Delta.Message == nil {
		// Non-content events (stream-start, content-end, message-end, etc.)
		// trigger a flush before passing through.
		c.Flush()
		writePipe(c.opts.pw,
			[]byte(sseDataPrefix),
			[]byte(c.opts.replacer.Replace(string(payload))),
			[]byte("\n"))
		return true
	}

	c.lastIndex = envelope.Index
	text := envelope.Delta.Message.Content.Text
	if text == "" {
		writePipe(c.opts.pw,
			[]byte(sseDataPrefix),
			[]byte(c.opts.replacer.Replace(string(payload))),
			[]byte("\n"))
		return true
	}

	c.textAccum.WriteString(text)
	accumulated := c.textAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return true
	}

	toReplace := accumulated[:flushUpTo]
	replaced := c.opts.replacer.Replace(toReplace)
	if toReplace != replaced && c.opts.verbose {
		log.Printf("[DEANON] cohere text replaced: sessionID=%s tokens=%d", c.opts.sessionID, c.opts.tokenCount)
	}

	envelope.Delta.Message.Content.Text = replaced
	newPayload, err := json.Marshal(envelope)
	if err != nil {
		return false
	}

	writePipe(c.opts.pw, []byte(sseDataPrefix), newPayload, []byte("\n"))

	remaining := accumulated[flushUpTo:]
	c.textAccum.Reset()
	c.textAccum.WriteString(remaining)
	return true
}

// Flush emits any remaining accumulated text as a synthetic content-delta event.
func (c *cohereDeanonymizer) Flush() {
	if c.textAccum.Len() == 0 {
		return
	}
	flushed := c.opts.replacer.Replace(c.textAccum.String())
	if flushed != "" {
		synth := cohereEnvelope{
			Type:  "content-delta",
			Index: c.lastIndex,
			Delta: &cohereDelta{
				Message: &cohereMessage{
					Content: cohereContent{Text: flushed},
				},
			},
		}
		if b, err := json.Marshal(synth); err == nil {
			writePipe(c.opts.pw, []byte(sseDataPrefix), b, []byte("\n\n"))
		}
	}
	c.textAccum.Reset()
}
