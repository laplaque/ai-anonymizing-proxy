package anonymizer

import (
	"log"
	"strings"
)

// replicateDeanonymizer handles Replicate's plain-text SSE format.
// Replicate output events carry plain text in the data field (not JSON).
// The accumulator provides token-split protection across chunks.
type replicateDeanonymizer struct {
	opts      streamDeanonymizerOpts
	textAccum strings.Builder
}

func newReplicateDeanonymizer(opts streamDeanonymizerOpts) *replicateDeanonymizer {
	return &replicateDeanonymizer{opts: opts}
}

// ProcessDataPayload accumulates plain text from Replicate output events.
// Returns false for empty JSON payloads like {} (done events), letting the
// framework apply raw replacement.
func (r *replicateDeanonymizer) ProcessDataPayload(payload []byte) bool {
	text := strings.TrimSpace(string(payload))

	// The done event sends "data: {}" — not meaningful text.
	if text == "{}" || text == "" {
		r.Flush()
		writePipe(r.opts.pw, []byte(sseDataPrefix), payload, []byte("\n"))
		return true
	}

	r.textAccum.WriteString(text)
	accumulated := r.textAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return true
	}

	toReplace := accumulated[:flushUpTo]
	replaced := r.opts.replacer.Replace(toReplace)
	if toReplace != replaced && r.opts.verbose {
		log.Printf("[DEANON] replicate text replaced: sessionID=%s tokens=%d", r.opts.sessionID, r.opts.tokenCount)
	}

	writePipe(r.opts.pw, []byte(sseDataPrefix), []byte(replaced), []byte("\n"))

	remaining := accumulated[flushUpTo:]
	r.textAccum.Reset()
	r.textAccum.WriteString(remaining)
	return true
}

// Flush emits any remaining accumulated text with token replacement.
func (r *replicateDeanonymizer) Flush() {
	if r.textAccum.Len() == 0 {
		return
	}
	flushed := r.opts.replacer.Replace(r.textAccum.String())
	if flushed != "" {
		writePipe(r.opts.pw, []byte(sseDataPrefix), []byte(flushed), []byte("\n\n"))
	}
	r.textAccum.Reset()
}
