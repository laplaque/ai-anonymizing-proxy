package anonymizer

// passthroughDeanonymizer applies raw token replacement to SSE data payloads
// without JSON parsing or accumulation. Used for unknown providers.
type passthroughDeanonymizer struct {
	opts streamDeanonymizerOpts
}

func newPassthroughDeanonymizer(opts streamDeanonymizerOpts) *passthroughDeanonymizer {
	return &passthroughDeanonymizer{opts: opts}
}

// ProcessDataPayload applies token replacement to the entire payload and
// writes it through. No accumulation is performed, so token-split protection
// is limited to the non-streaming DeanonymizeText path for buffered responses.
func (p *passthroughDeanonymizer) ProcessDataPayload(payload []byte) bool {
	replaced := p.opts.replacer.Replace(string(payload))
	writePipe(p.opts.pw, []byte(sseDataPrefix), []byte(replaced), []byte("\n"))
	return true
}

// Flush is a no-op — passthrough does not accumulate state between payloads.
// Required for streamDeanonymizer interface compliance.
func (p *passthroughDeanonymizer) Flush() {}
