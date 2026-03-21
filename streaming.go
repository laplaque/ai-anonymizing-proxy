package anonymizer

import (
	"bytes"
	"encoding/json"
	"io"
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

// tokenSuffixLen is the number of bytes kept unflushed in the streaming
// accumulator to guard against partial token splits. The longest possible
// token is [PII_CREDITCARD_XXXXXXXXXXXXXXXX] at 27 bytes; 28 gives one byte margin.
const tokenSuffixLen = 28

// safeCutPoint returns the byte index up to which accumulated text can be
// safely flushed without splitting a partial PII token. It scans backward
// from the suffix guard boundary looking for an unmatched '['.
// Returns 0 if all text should be held in the accumulator.
func safeCutPoint(accumulated string) int {
	if len(accumulated) <= tokenSuffixLen {
		return 0
	}

	cutAt := len(accumulated) - tokenSuffixLen
	for i := len(accumulated) - 1; i >= cutAt; i-- {
		if accumulated[i] == '[' {
			if !strings.ContainsRune(accumulated[i:], ']') {
				cutAt = i
			}
			break
		}
	}
	return cutAt
}

// streamContext holds the mutable state shared by the streaming helper
// functions during a single StreamingDeanonymize invocation.
type streamContext struct {
	pw            *io.PipeWriter
	replacer      *strings.Replacer
	textAccum     strings.Builder
	jsonAccum     strings.Builder
	lastIndex     int // content block index from the most recent text_delta
	lastJSONIndex int // content block index from the most recent input_json_delta
	sessionID     string
	verbose       bool
	tokenCount    int
}

// processTextDelta handles a text_delta or thinking_delta SSE event by
// accumulating text and flushing safe prefixes with token replacement.
func processTextDelta(ctx *streamContext, envelope *sseEnvelope) error {
	ctx.lastIndex = envelope.Index
	ctx.textAccum.WriteString(envelope.Delta.Text)
	accumulated := ctx.textAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return nil
	}

	toReplace := accumulated[:flushUpTo]
	replaced := ctx.replacer.Replace(toReplace)
	if toReplace != replaced && ctx.verbose {
		log.Printf("[DEANON] text replaced: sessionID=%s tokens=%d", ctx.sessionID, ctx.tokenCount)
	}

	envelope.Delta.Text = replaced
	newPayload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	ctx.pw.Write([]byte(sseDataPrefix)) //nolint:errcheck
	ctx.pw.Write(newPayload)            //nolint:errcheck
	ctx.pw.Write([]byte("\n"))          //nolint:errcheck

	remaining := accumulated[flushUpTo:]
	ctx.textAccum.Reset()
	ctx.textAccum.WriteString(remaining)
	return nil
}

// flushRemainder emits a synthetic content_block_delta carrying any text
// still held in the accumulator, with token replacement applied.
func flushRemainder(ctx *streamContext) {
	if ctx.textAccum.Len() == 0 {
		return
	}
	flushed := ctx.replacer.Replace(ctx.textAccum.String())
	if flushed != "" {
		// Use the last-seen content block index so that thinking (index 0)
		// and text (index 1) blocks flush to their correct position.
		synth := map[string]any{
			"type":  "content_block_delta",
			"index": ctx.lastIndex,
			"delta": map[string]string{"type": "text_delta", "text": flushed},
		}
		if b, err := json.Marshal(synth); err == nil {
			ctx.pw.Write([]byte(sseDataPrefix)) //nolint:errcheck
			ctx.pw.Write(b)                     //nolint:errcheck
			ctx.pw.Write([]byte("\n\n"))        //nolint:errcheck
		}
	}
	ctx.textAccum.Reset()
}

// processJSONDelta handles an input_json_delta SSE event by accumulating
// partial_json fragments and flushing safe prefixes with token replacement.
func processJSONDelta(ctx *streamContext, envelope *sseEnvelope) error {
	ctx.lastJSONIndex = envelope.Index
	ctx.jsonAccum.WriteString(envelope.Delta.PartialJSON)
	accumulated := ctx.jsonAccum.String()

	flushUpTo := safeCutPoint(accumulated)
	if flushUpTo == 0 {
		return nil
	}

	toReplace := accumulated[:flushUpTo]
	replaced := ctx.replacer.Replace(toReplace)
	if toReplace != replaced && ctx.verbose {
		log.Printf("[DEANON] json replaced: sessionID=%s tokens=%d", ctx.sessionID, ctx.tokenCount)
	}

	envelope.Delta.PartialJSON = replaced
	newPayload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	ctx.pw.Write([]byte(sseDataPrefix)) //nolint:errcheck
	ctx.pw.Write(newPayload)            //nolint:errcheck
	ctx.pw.Write([]byte("\n"))          //nolint:errcheck

	remaining := accumulated[flushUpTo:]
	ctx.jsonAccum.Reset()
	ctx.jsonAccum.WriteString(remaining)
	return nil
}

// flushJSONRemainder emits a synthetic content_block_delta carrying any
// partial_json still held in the JSON accumulator, with token replacement.
func flushJSONRemainder(ctx *streamContext) {
	if ctx.jsonAccum.Len() == 0 {
		return
	}
	flushed := ctx.replacer.Replace(ctx.jsonAccum.String())
	if flushed != "" {
		synth := map[string]any{
			"type":  "content_block_delta",
			"index": ctx.lastJSONIndex,
			"delta": map[string]string{"type": "input_json_delta", "partial_json": flushed},
		}
		if b, err := json.Marshal(synth); err == nil {
			ctx.pw.Write([]byte(sseDataPrefix)) //nolint:errcheck
			ctx.pw.Write(b)                     //nolint:errcheck
			ctx.pw.Write([]byte("\n\n"))        //nolint:errcheck
		}
	}
	ctx.jsonAccum.Reset()
}

// processLine handles one complete SSE line (without trailing newline).
// It dispatches text_delta events to processTextDelta, flushes accumulated
// text on non-text-delta events, and passes through non-data lines.
func processLine(ctx *streamContext, line []byte) {
	if len(line) == 0 || line[0] == ':' {
		ctx.pw.Write(line)         //nolint:errcheck
		ctx.pw.Write([]byte("\n")) //nolint:errcheck
		return
	}

	if !bytes.HasPrefix(line, []byte(sseDataPrefix)) {
		ctx.pw.Write([]byte(ctx.replacer.Replace(string(line)))) //nolint:errcheck
		ctx.pw.Write([]byte("\n"))                               //nolint:errcheck
		return
	}

	payload := line[len(sseDataPrefix):]

	var envelope sseEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		ctx.pw.Write([]byte(sseDataPrefix))                         //nolint:errcheck
		ctx.pw.Write([]byte(ctx.replacer.Replace(string(payload)))) //nolint:errcheck
		ctx.pw.Write([]byte("\n"))                                  //nolint:errcheck
		return
	}

	isDeltaText := envelope.Type == "content_block_delta" &&
		envelope.Delta != nil &&
		(envelope.Delta.Type == "text_delta" || envelope.Delta.Type == "thinking_delta")

	isJSONDelta := envelope.Type == "content_block_delta" &&
		envelope.Delta != nil &&
		envelope.Delta.Type == "input_json_delta"

	if isDeltaText {
		if err := processTextDelta(ctx, &envelope); err != nil {
			ctx.pw.Write(line)         //nolint:errcheck
			ctx.pw.Write([]byte("\n")) //nolint:errcheck
			ctx.textAccum.Reset()
		}
		return
	}

	if isJSONDelta {
		if err := processJSONDelta(ctx, &envelope); err != nil {
			ctx.pw.Write(line)         //nolint:errcheck
			ctx.pw.Write([]byte("\n")) //nolint:errcheck
			ctx.jsonAccum.Reset()
		}
		return
	}

	flushRemainder(ctx)
	flushJSONRemainder(ctx)
	ctx.pw.Write([]byte(ctx.replacer.Replace(string(line)))) //nolint:errcheck
	ctx.pw.Write([]byte("\n"))                               //nolint:errcheck
}

// assembleLines processes raw bytes from a read chunk, appending them to
// lineBuf. Each time a newline is encountered the complete line (with \r
// stripped) is dispatched to processLine and lineBuf is reset.
func assembleLines(chunk []byte, lineBuf []byte, ctx *streamContext) []byte {
	for _, b := range chunk {
		if b == '\n' {
			line := lineBuf
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			processLine(ctx, line)
			lineBuf = lineBuf[:0]
		} else {
			lineBuf = append(lineBuf, b)
		}
	}
	return lineBuf
}

// handleStreamEnd flushes any partial line and accumulated text when the
// source reader returns an error (including io.EOF).
func handleStreamEnd(lineBuf []byte, readErr error, ctx *streamContext) {
	if len(lineBuf) > 0 {
		ctx.pw.Write([]byte(ctx.replacer.Replace(string(lineBuf)))) //nolint:errcheck
	}
	flushRemainder(ctx)
	flushJSONRemainder(ctx)
	if readErr != io.EOF {
		log.Printf("[ANONYMIZER] StreamingDeanonymize read error: %v", readErr)
		ctx.pw.CloseWithError(readErr) //nolint:errcheck
	}
}

// readLoop reads from src, assembling complete lines and dispatching them
// to processLine. At EOF it flushes any remaining partial line and
// accumulated text via handleStreamEnd.
func readLoop(src io.ReadCloser, ctx *streamContext) {
	defer src.Close()    //nolint:errcheck
	defer ctx.pw.Close() //nolint:errcheck

	var lineBuf []byte
	const chunkSize = 32 * 1024
	buf := make([]byte, chunkSize)

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			lineBuf = assembleLines(buf[:n], lineBuf, ctx)
		}
		if readErr != nil {
			handleStreamEnd(lineBuf, readErr, ctx)
			return
		}
	}
}
